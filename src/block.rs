use crate::proto::{self};
use crate::proto::{BlockContext, BlockEffects};
use crate::utils::program::common::build_versioned_message;
use agave_feature_set::*;
use prost::Message;
#[allow(deprecated)]
use solana_account::AccountSharedData;
use solana_accounts_db::accounts::Accounts;
use solana_accounts_db::accounts_db::{AccountsDb, AccountsDbConfig};
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_hash::AccountsLtHash;
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimitMb};
use solana_accounts_db::ancestors::AncestorsForSerialization;
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_clock::Epoch;
use solana_cluster_type::ClusterType;
use solana_entry::entry::{Entry, VerifyRecyclers};
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_genesis_config::GenesisConfig;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_lattice_hash::lt_hash::LtHash;
use solana_ledger::blockstore_processor::{
    confirm_slot_entries, create_thread_pool, ConfirmationProgress, ConfirmationTiming,
};
use solana_ledger::leader_schedule_cache::LeaderScheduleCache;
use solana_poh_config::PohConfig;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_runtime::bank::bank_hash_details::{BankHashDetails, SlotDetails};
use solana_runtime::bank::{null_tracer, Bank, BankFieldsToDeserialize, BankHashStats, BankRc};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_runtime::installed_scheduler_pool::BankWithScheduler;
use solana_runtime::prioritization_fee_cache::PrioritizationFeeCache;
use solana_runtime::rent_collector::RentCollector;
use solana_runtime::runtime_config::RuntimeConfig;
use solana_runtime::stake_account;
use solana_runtime::stake_history::StakeHistory;
use solana_runtime::stakes::{SerdeStakesToStakeFormat, Stakes};
use solana_sdk_ids::sysvar::stake_history;
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
use std::path::PathBuf;
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
    let Ok(block_context) = BlockContext::decode(&in_slice[..in_sz as usize]) else {
        return 0;
    };

    let Some(block_result) = execute_block(block_context) else {
        return 0;
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

    stakes.epoch = epoch;
    stakes.stake_history = stake_history.clone();
    stakes
}

/* Build stake delegations for previous epochs. The difference between this and `build_latest_stake_deleations()` is that
we use the provided votes cache instead of the latest input account states. */
fn build_prev_stake_delegations(
    vote_accounts: &[proto::VoteAccount],
) -> Stakes<stake_account::StakeAccount<Delegation>> {
    let mut stakes = Stakes::<Delegation>::default();
    vote_accounts.iter().for_each(|input_vote_account| {
        let (pubkey, account) = input_vote_account
            .vote_account
            .clone()
            .unwrap()
            .try_into()
            .unwrap();

        /* Due to the way Agave and FD's stakes caches differ, we need to use the latest account states for the current epoch's stake delegations */
        let account_shared_data = AccountSharedData::from(account);

        if let Ok(vote_account) = VoteAccount::try_from(account_shared_data) {
            stakes.vote_accounts.insert(pubkey, vote_account, || input_vote_account.stake);
        }
    });

    let stake_accounts: Stakes<stake_account::StakeAccount<Delegation>> =
        Stakes::new(&stakes, |pubkey| {
            stakes
                .vote_accounts
                .get(pubkey)
                .map(|vote_account| vote_account.account().clone())
        })
        .unwrap();
    stake_accounts
}

#[allow(deprecated)]
pub fn execute_block(context: BlockContext) -> Option<BlockEffects> {
    let slot_ctx = context.slot_ctx.unwrap();
    let epoch_ctx = context.epoch_ctx.unwrap();
    let fd_features = epoch_ctx.features.unwrap_or_default();
    let feature_set = FeatureSet::from(&fd_features);
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
        .find(|item| item.address.as_slice() == stake_history::id().as_ref() && item.lamports > 0)
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
    ancestors.insert(slot.saturating_sub(1), 1);
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
    accounts.store_accounts_seq((slot.saturating_sub(1), &accounts_to_store[..]), None);

    /* Build the stakes separately */
    let epoch = epoch_schedule.get_epoch(slot);
    let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(slot);
    let stakes_t = build_latest_stake_delegations(&context.acct_states, epoch, &stake_history);
    let stakes_t_1 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_1);
    let stakes_t_2 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_2);

    let mut epoch_stakes: HashMap<Epoch, VersionedEpochStakes> = HashMap::new();
    epoch_stakes.insert(
        leader_schedule_epoch.saturating_sub(2),
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_2),
            leader_schedule_epoch.saturating_sub(2),
        ),
    );
    epoch_stakes.insert(
        leader_schedule_epoch.saturating_sub(1),
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_1.clone()),
            leader_schedule_epoch.saturating_sub(1),
        ),
    );

    let stakes_current_accounts = Stakes::new(&stakes_t, |pubkey| {
        context
            .acct_states
            .iter()
            .find(|acct| {
                Pubkey::new_from_array(acct.address.clone().try_into().unwrap()) == *pubkey
            })
            .map(AccountSharedData::from)
    })
    .unwrap();
    epoch_stakes.insert(
        leader_schedule_epoch,
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_current_accounts),
            leader_schedule_epoch,
        ),
    );

    let fee_rate_governor = slot_ctx.fee_rate_governor.unwrap();

    let bank_fields = BankFieldsToDeserialize {
        blockhash_queue,
        ancestors,
        hash: Hash::default(),
        parent_hash: Hash::new_from_array(slot_ctx.parent_bank_hash.try_into().unwrap()),
        parent_slot: slot_ctx.prev_slot,
        hard_forks: HardForks::default(),
        transaction_count: 0,
        hashes_per_tick: None,
        capitalization: slot_ctx.prev_epoch_capitalization,
        signature_count: 0,
        tick_height: 64u64.saturating_mul(slot),
        max_tick_height: 64u64.saturating_mul(slot.saturating_add(1)),
        ticks_per_slot: 64u64,
        ns_per_slot: genesis_config.ns_per_slot(),
        genesis_creation_time: epoch_ctx.genesis_creation_time as i64,
        slots_per_year: genesis_config.slots_per_year(),
        slot,
        epoch,
        block_height: slot_ctx.block_height,
        collector_id: Pubkey::default(),
        collector_fees: 0,
        fee_rate_governor: FeeRateGovernor::new_derived(
            &FeeRateGovernor {
                lamports_per_signature,
                target_lamports_per_signature: fee_rate_governor.target_lamports_per_signature,
                target_signatures_per_slot: fee_rate_governor.target_signatures_per_slot,
                min_lamports_per_signature: fee_rate_governor.min_lamports_per_signature,
                max_lamports_per_signature: fee_rate_governor.max_lamports_per_signature,
                burn_percent: fee_rate_governor.burn_percent as u8,
            },
            slot_ctx.parent_signature_count,
        ),
        rent_collector: RentCollector {
            epoch: epoch_schedule.get_epoch(slot),
            epoch_schedule: epoch_schedule.clone(),
            slots_per_year: epoch_ctx.slots_per_year,
            rent,
        },
        epoch_schedule,
        inflation: epoch_ctx.inflation.unwrap().into(),
        stakes: stakes_t,
        versioned_epoch_stakes: epoch_stakes,
        is_delta: false,
        accounts_data_len: 0,
        accounts_lt_hash: AccountsLtHash(LtHash::identity()),
        bank_hash_stats: BankHashStats::default(),
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

    // Seed initial accounts into the bank
    for account in &context.acct_states {
        let pubkey = Pubkey::new_from_array(account.address.clone().try_into().unwrap());
        let account_data = AccountSharedData::from(account);
        bank.store_account(&pubkey, &account_data);
    }

    let leader_schedule = LeaderScheduleCache::new_from_bank(&bank);
    let leader = leader_schedule
        .slot_leader_at(slot, None)
        .unwrap_or_default();
    bank.set_collector_id_for_tests(leader);

    let current_epoch = bank.epoch_schedule().get_epoch(bank.slot());
    let parent_epoch = bank.epoch_schedule().get_epoch(bank.parent_slot());

    /* Have we crossed an epoch boundary? */
    if parent_epoch < current_epoch {
        bank.process_new_epoch(
            parent_epoch,
            current_epoch,
            bank.block_height(),
            null_tracer(),
        );
    }
    bank.distribute_partitioned_epoch_rewards();

    bank.get_transaction_processor().reset_sysvar_cache();
    bank.update_slot_hashes();
    bank.update_stake_history(Some(parent_epoch));
    bank.update_clock(Some(parent_epoch));
    bank.update_last_restart_slot();
    bank.update_recent_blockhashes();
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(&bank);

    let bank_forks = BankForks::new_rw_arc(bank);
    let bank = bank_forks.write().unwrap().root_bank();

    let mut entries = vec![Entry::new_tick(1, &poh); 64];
    entries.extend(
        context
            .txns
            .iter()
            .map(|txn| {
                let message = build_versioned_message(txn.message.as_ref()?);
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
            .collect::<Option<Vec<Entry>>>()?,
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
    let cost_tracker = no_schedule_bank.read_cost_tracker().unwrap();

    if std::env::var("AGAVE_SOLCAP_DIR").is_ok() {
        let slot_details = SlotDetails::new_from_bank(no_schedule_bank.as_ref(), true).unwrap();
        let details = BankHashDetails::new(vec![slot_details]);
        let parent_dir: PathBuf = std::env::var("AGAVE_SOLCAP_DIR").unwrap().into();
        let path = parent_dir.join(details.filename().unwrap());
        if !path.exists() {
            _ = std::fs::create_dir_all(parent_dir);
            let file = std::fs::File::create(&path).unwrap();
            let writer = std::io::BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &details).unwrap();
        }
    }

    Some(BlockEffects {
        has_error: result.is_err(),
        slot_capitalization: no_schedule_bank.capitalization(),
        bank_hash: no_schedule_bank.hash().to_bytes().to_vec(),
        cost_tracker: Some(proto::CostTracker {
            block_cost: cost_tracker.block_cost(),
            vote_cost: cost_tracker.vote_cost(),
        }),
    })
}
