use crate::proto::{self};
use crate::proto::{BlockContext, BlockEffects};
use crate::utils::program::common::build_versioned_message;
use crate::TOGGLE_DIRECT_MAPPING;
use agave_feature_set::*;
use prost::Message;
#[allow(deprecated)]
use solana_account::AccountSharedData;
use solana_accounts_db::accounts::Accounts;
use solana_accounts_db::accounts_db::{AccountsDb, AccountsDbConfig};
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimitMb};
use solana_accounts_db::ancestors::AncestorsForSerialization;
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_clock::Epoch;
use solana_cluster_type::ClusterType;
use solana_entry::entry::{Entry, VerifyRecyclers};
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_genesis_config::GenesisConfig;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_ledger::blockstore_processor::{
    confirm_slot_entries, create_thread_pool, ConfirmationProgress, ConfirmationTiming,
};
use solana_ledger::leader_schedule_cache::LeaderScheduleCache;
use solana_poh_config::PohConfig;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_rent_collector::RentCollector;
use solana_runtime::bank::{Bank, BankFieldsToDeserialize, BankRc};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::epoch_stakes::EpochStakes;
use solana_runtime::installed_scheduler_pool::BankWithScheduler;
use solana_runtime::prioritization_fee_cache::PrioritizationFeeCache;
use solana_runtime::runtime_config::RuntimeConfig;
use solana_runtime::stake_account;
use solana_runtime::stake_history::StakeHistory;
use solana_runtime::stakes::{Stakes, StakesEnum};
use solana_signature::Signature;
use solana_stake_interface::state::Delegation;
use solana_sysvar;
#[allow(deprecated)]
use solana_sysvar::recent_blockhashes::RecentBlockhashes;
use solana_transaction::versioned::VersionedTransaction;
use solana_vote::vote_account::VoteAccount;
use std::collections::HashMap;
use std::ffi::c_int;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_block_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let block_context = match BlockContext::decode(&in_slice[..in_sz as usize]) {
        Ok(context) => context,
        Err(_) => return 0, // Decode error
    };

    let block_result = match execute_block(block_context) {
        Some(value) => value,
        None => return 0, // Data format error
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = block_result.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }

    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

impl From<proto::Inflation> for Inflation {
    fn from(input: proto::Inflation) -> Self {
        let mut inflation = Inflation::default();
        inflation.initial = input.initial;
        inflation.terminal = input.terminal;
        inflation.taper = input.taper;
        inflation.foundation = input.foundation;
        inflation.foundation_term = input.foundation_term;
        inflation
    }
}

/* This is a little bit hacky because there's no direct Agave API that gets us a populated Stakes<Delegation> object
from a set of account states. Fine, I'll do it myself... */
fn build_latest_stake_delegations(
    account_states: &[proto::AcctState],
    epoch: Epoch,
    stake_history: &StakeHistory,
) -> Stakes<Delegation> {
    let mut stakes = Stakes::<Delegation>::default();

    /* First populate the stake delegations. We only consider stake accounts with nonzero lamports and stake amount. */
    account_states
        .iter()
        .filter(|item| item.lamports > 0)
        .for_each(|account_state| {
            let pubkey = Pubkey::new_from_array(account_state.address.clone().try_into().unwrap());
            let account_shared_data = AccountSharedData::from(account_state);
            if let Ok(stake_account) =
                stake_account::StakeAccount::<Delegation>::try_from(account_shared_data)
            {
                /* Skip nonzero delegations */
                if stake_account.delegation().stake > 0 {
                    stakes
                        .stake_delegations
                        .insert(pubkey, *stake_account.delegation());
                }
            }
        });

    /* Then populate the vote accounts */
    account_states
        .iter()
        .filter(|item| item.lamports > 0)
        .for_each(|account_state| {
            let pubkey = Pubkey::new_from_array(account_state.address.clone().try_into().unwrap());
            let account_shared_data = AccountSharedData::from(account_state);
            if let Ok(vote_account) = VoteAccount::try_from(account_shared_data) {
                /* Note we can pass in new_rate_activation_epoch = 0 because the feature is activated on all clusters */
                stakes.vote_accounts.insert(pubkey, vote_account, || {
                    stakes
                        .stake_delegations
                        .values()
                        .filter(|delegation| delegation.voter_pubkey == pubkey)
                        .map(|delegation| delegation.stake(epoch, stake_history, Some(0)))
                        .sum()
                });
            }
        });

    stakes
}

/* Build stake delegations for previous epochs. The difference between this and `build_latest_stake_deleations()` is that
we use the provided votes cache instead of the latest input account states. */
fn build_prev_stake_delegations(vote_accounts: &[proto::VoteAccount]) -> Stakes<Delegation> {
    let mut stakes = Stakes::<Delegation>::default();
    vote_accounts.iter().for_each(|vote_account| {
        let (pubkey, account) = vote_account
            .vote_account
            .clone()
            .unwrap()
            .try_into()
            .unwrap();

        /* Due to the way Agave and FD's stakes caches differ, we need to use the latest account states for the current epoch's stake delegations */
        let account_shared_data = AccountSharedData::from(account);

        stakes.vote_accounts.insert(
            pubkey,
            VoteAccount::try_from(account_shared_data).unwrap(),
            || vote_account.stake,
        );
    });
    stakes
}

#[allow(deprecated)]
pub fn execute_block(context: BlockContext) -> Option<BlockEffects> {
    let slot_ctx = context.slot_ctx.unwrap();
    let epoch_ctx = context.epoch_ctx.unwrap();
    let fd_features = epoch_ctx.features.unwrap_or_default();
    let mut feature_set = FeatureSet::from(&fd_features);

    unsafe {
        if TOGGLE_DIRECT_MAPPING {
            // Toggle the BPF direct mapping feature
            if feature_set
                .active()
                .contains_key(&bpf_account_data_direct_mapping::id())
            {
                feature_set.deactivate(&bpf_account_data_direct_mapping::id());
            } else {
                feature_set.activate(&bpf_account_data_direct_mapping::id(), 0);
            }
        }
    }

    let slot = slot_ctx.slot;
    let poh = Hash::new_from_array(slot_ctx.poh.clone().try_into().unwrap());

    /* HACK: Because there are three different schedules and rent instances, we need to find and deserialize
    them from the account states first. Technically these different rent / epoch schedules should be fuzzed,
    but that will be out of scope for this fuzzer. */
    let rent: Rent = context
        .acct_states
        .iter()
        .find(|item| {
            item.address.as_slice() == solana_sysvar::rent::id().as_ref() && item.lamports > 0
        })
        .map(|account| bincode::deserialize(&account.data).unwrap())
        .unwrap();
    let epoch_schedule: EpochSchedule = context
        .acct_states
        .iter()
        .find(|item| {
            item.address.as_slice() == solana_sysvar::epoch_schedule::id().as_ref()
                && item.lamports > 0
        })
        .map(|account| bincode::deserialize(&account.data).unwrap())
        .unwrap();
    let recent_blockhashes: RecentBlockhashes = context
        .acct_states
        .iter()
        .find(|item| {
            item.address.as_slice() == solana_sysvar::recent_blockhashes::id().as_ref()
                && item.lamports > 0
        })
        .map(|account| bincode::deserialize(&account.data).unwrap())
        .unwrap();
    let stake_history: StakeHistory = context
        .acct_states
        .iter()
        .find(|item| {
            item.address.as_slice() == solana_sysvar::stake_history::id().as_ref()
                && item.lamports > 0
        })
        .map(|account| bincode::deserialize(&account.data).unwrap())
        .unwrap();
    let genesis_config = GenesisConfig {
        creation_time: epoch_ctx.genesis_creation_time as i64,
        inflation: epoch_ctx.inflation.unwrap().into(),
        epoch_schedule: epoch_schedule.clone(),
        cluster_type: ClusterType::Development,
        poh_config: PohConfig {
            target_tick_duration: Duration::from_micros(6250), /* TODO: Restore this from input */
            ..PohConfig::default()
        },
        ..GenesisConfig::default()
    };

    let lamports_per_signature = recent_blockhashes
        .first()
        .map(|blockhash| blockhash.fee_calculator.lamports_per_signature)
        .unwrap_or(5000u64);

    let mut blockhash_queue = BlockhashQueue::default();
    context.blockhash_queue.iter().for_each(|blockhash| {
        let blockhash_hash = Hash::new_from_array(blockhash.clone().try_into().unwrap());
        blockhash_queue.register_hash(&blockhash_hash, lamports_per_signature);
    });

    let mut ancestors = AncestorsForSerialization::default();
    ancestors.insert(slot - 1, 1);
    ancestors.insert(slot, 1);

    /* Accounts DB config and initialization */
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit_mb: IndexLimitMb::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = Some(AccountsDbConfig {
        index,
        storage_access: StorageAccess::File,
        skip_initial_hash_calc: true,
        num_hash_threads: Some(NonZeroUsize::new(1).unwrap()),
        ..AccountsDbConfig::default()
    });
    let accounts_db = AccountsDb::new_with_config(
        vec![],
        accounts_db_config,
        None,
        Arc::new(AtomicBool::new(false)),
    );
    let accounts = Accounts::new(Arc::new(accounts_db));
    let accounts_to_store = context
        .acct_states
        .iter()
        .map(|account| {
            let pubkey = Pubkey::new_from_array(account.address.clone().try_into().unwrap());
            let account_data = AccountSharedData::from(account);
            (pubkey, account_data)
        })
        .collect::<Vec<_>>();
    accounts.store_cached((slot - 1, &accounts_to_store[..]), None);

    /* Build the stakes separately */
    let epoch = epoch_schedule.get_epoch(slot);
    let stakes_t = build_latest_stake_delegations(&context.acct_states, epoch, &stake_history);

    let stakes_t_1 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_1);
    let stake_accounts_t_1 = Stakes::new(&stakes_t_1, |pubkey| {
        let account = epoch_ctx
            .vote_accounts_t_1
            .iter()
            .find(|vote_account| {
                Pubkey::new_from_array(
                    vote_account
                        .vote_account
                        .as_ref()
                        .unwrap()
                        .address
                        .clone()
                        .try_into()
                        .unwrap(),
                ) == *pubkey
            })
            .map(|vote_account| vote_account.vote_account.as_ref().unwrap().clone())
            .unwrap();
        Some(AccountSharedData::from(&account))
    })
    .unwrap();

    let stakes_t_2 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_2);
    let stake_accounts_t_2 = Stakes::new(&stakes_t_2, |pubkey| {
        let account = epoch_ctx
            .vote_accounts_t_2
            .iter()
            .find(|vote_account| {
                Pubkey::new_from_array(
                    vote_account
                        .vote_account
                        .as_ref()
                        .unwrap()
                        .address
                        .clone()
                        .try_into()
                        .unwrap(),
                ) == *pubkey
            })
            .map(|vote_account| vote_account.vote_account.as_ref().unwrap().clone())
            .unwrap();
        Some(AccountSharedData::from(&account))
    })
    .unwrap();

    let mut epoch_stakes: HashMap<Epoch, EpochStakes> = HashMap::new();
    epoch_stakes.insert(
        epoch.saturating_sub(1),
        EpochStakes::new(
            Arc::new(StakesEnum::from(stake_accounts_t_2)),
            epoch.saturating_sub(1),
        ),
    );
    epoch_stakes.insert(
        epoch,
        EpochStakes::new(
            Arc::new(StakesEnum::from(stake_accounts_t_1.clone())),
            epoch,
        ),
    );

    epoch_stakes.insert(
        epoch + 1,
        EpochStakes::new(Arc::new(StakesEnum::from(stakes_t.clone())), epoch + 1),
    );

    let bank_fields = BankFieldsToDeserialize {
        blockhash_queue,
        ancestors,
        hash: Hash::default(),
        parent_hash: Hash::new_from_array(slot_ctx.parent_bank_hash.try_into().unwrap()),
        parent_slot: slot_ctx.prev_slot,
        capitalization: slot_ctx.prev_epoch_capitalization,
        tick_height: 64u64 * slot,
        max_tick_height: 64u64 * (slot + 1u64),
        ticks_per_slot: 64u64,
        ns_per_slot: genesis_config.ns_per_slot(),
        genesis_creation_time: epoch_ctx.genesis_creation_time as i64,
        slots_per_year: genesis_config.slots_per_year(),
        slot,
        epoch,
        block_height: slot_ctx.block_height,
        fee_rate_governor: FeeRateGovernor {
            lamports_per_signature,
            target_lamports_per_signature: 10000,
            target_signatures_per_slot: 20000,
            min_lamports_per_signature: 5000,
            max_lamports_per_signature: 100000,
            burn_percent: 50,
        },
        rent_collector: RentCollector {
            epoch: epoch_schedule.get_epoch(slot),
            epoch_schedule: epoch_schedule.clone(),
            slots_per_year: epoch_ctx.slots_per_year,
            rent,
        },
        epoch_schedule,
        inflation: epoch_ctx.inflation.unwrap().into(),
        stakes: stakes_t,
        epoch_stakes,
        ..BankFieldsToDeserialize::default()
    };

    let bank_rc = BankRc::new(accounts);
    let mut bank = Bank::new_from_fields(
        bank_rc,
        &genesis_config,
        Arc::new(RuntimeConfig::default()),
        bank_fields,
        None,
        None,
        false,
        0,
        Some(feature_set),
    );

    let leader_schedule = LeaderScheduleCache::new_from_bank(&bank);
    let leader = leader_schedule
        .slot_leader_at(slot, None)
        .unwrap_or_default();
    bank.set_collector_id_for_tests(leader);

    let bank_forks = BankForks::new_rw_arc(bank);
    let bank = bank_forks.write().unwrap().root_bank();

    bank.get_transaction_processor().reset_sysvar_cache();
    bank.update_slot_hashes();
    bank.update_clock(None);
    bank.update_recent_blockhashes();
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(bank.as_ref());

    let mut entries = vec![Entry::new_tick(1, &poh); 64];
    entries.extend(
        context
            .microblocks
            .iter()
            .flat_map(|microblock| microblock.txns.iter())
            .filter_map(|txn| {
                let message = txn.message.as_ref().and_then(build_versioned_message)?;
                let signatures = txn
                    .signatures
                    .iter()
                    .map(|item| {
                        Signature::from(
                            <Vec<u8> as TryInto<[u8; 64]>>::try_into(item.clone()).unwrap(),
                        )
                    })
                    .collect::<Vec<Signature>>();

                let transaction = VersionedTransaction {
                    message,
                    signatures,
                };

                Some(Entry {
                    num_hashes: 1u64,
                    hash: Hash::default(),
                    transactions: vec![transaction],
                })
            })
            .collect::<Vec<Entry>>(),
    );

    let replay_tx_thread_pool = create_thread_pool(1);
    let no_schedule_bank = BankWithScheduler::new_without_scheduler(bank);
    let result = confirm_slot_entries(
        &no_schedule_bank,
        &replay_tx_thread_pool,
        (entries, 0u64, true),
        &mut ConfirmationTiming::default(),
        &mut ConfirmationProgress::default(),
        true,
        None,
        None,
        None,
        &VerifyRecyclers::default(),
        None,
        &PrioritizationFeeCache::new(0u64),
    );

    no_schedule_bank.freeze();

    Some(BlockEffects {
        has_error: result.is_err(),
        slot_capitalization: no_schedule_bank.capitalization(),
        bank_hash: no_schedule_bank.hash().to_bytes().to_vec(),
    })
}
