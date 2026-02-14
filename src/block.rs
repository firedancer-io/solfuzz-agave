use crate::proto::{self, AcctState};
use crate::proto::{BlockContext, BlockEffects};
use crate::utils::fd_hash::fd_hash;
use crate::utils::program::common::{build_versioned_message, get_sysvar};
use agave_feature_set::*;
use prost::Message;
#[allow(deprecated)]
use solana_account::{AccountSharedData, ReadableAccount};
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
use solana_ledger::leader_schedule_utils;
use solana_poh_config::PohConfig;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_runtime::bank::accounts_lt_hash::CacheValue as AccountsLtHashCacheValue;
use solana_runtime::bank::bank_hash_details::{
    AccountsDetails, BankHashComponents, BankHashDetails, SlotDetails,
};
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

// Firedancer-compatible seed for leader schedule hashing
const LEADER_SCHEDULE_HASH_SEED: u64 = 0xDEADFACE;

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
) -> Option<Stakes<Delegation>> {
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

    let mut total_stake = 0;
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
                    let s = stakes
                        .stake_delegations
                        .values()
                        .filter(|delegation| delegation.voter_pubkey == pubkey)
                        .map(|delegation| delegation.stake(epoch, stake_history, Some(0)))
                        .sum();
                    total_stake += s;
                    s
                });
            }
        });
    if total_stake == 0 { return None; }

    stakes.epoch = epoch;
    stakes.stake_history = stake_history.clone();
    Some(stakes)
}

/* Build stake delegations for previous epochs. The difference between this and `build_latest_stake_deleations()` is that
we use the provided votes cache instead of the latest input account states. */
fn build_prev_stake_delegations(
    vote_accounts: &[proto::VoteAccount],
) -> Option<Stakes<stake_account::StakeAccount<Delegation>>> {
    let mut stakes = Stakes::<Delegation>::default();
    let mut total_stake = 0;

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
            total_stake += input_vote_account.stake;
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
    if total_stake == 0 {
        return None;
    }
    Some(stake_accounts)
}

fn get_changed_accounts(
    initial_accounts: &[proto::AcctState],
    bank: &Bank,
) -> Vec<(Pubkey, AccountSharedData)> {
    let mut changed_accounts = Vec::new();

    for initial_account in initial_accounts {
        let pubkey = Pubkey::new_from_array(initial_account.address.clone().try_into().unwrap());
        let initial_account_data = AccountSharedData::from(initial_account);

        if let Some(current_account_data) = bank.get_account(&pubkey) {
            if accounts_differ(&initial_account_data, &current_account_data) {
                changed_accounts.push((pubkey, current_account_data));
            }
        } else if initial_account.lamports > 0 {
            changed_accounts.push((pubkey, AccountSharedData::default()));
        }
    }

    changed_accounts
}

fn accounts_differ(account1: &AccountSharedData, account2: &AccountSharedData) -> bool {
    account1.lamports() != account2.lamports()
        || account1.data() != account2.data()
        || account1.owner() != account2.owner()
        || account1.executable() != account2.executable()
}

fn create_changed_accounts_bank_hash_details(
    bank: &Bank,
    initial_accounts: &[proto::AcctState],
) -> Result<BankHashDetails, String> {
    let slot = bank.slot();
    if !bank.is_frozen() {
        return Err(format!(
            "Bank {slot} must be frozen in order to get bank hash details"
        ));
    }

    let full_slot_details = SlotDetails::new_from_bank(bank, true)?;
    let accounts_lt_hash_checksum = full_slot_details
        .bank_hash_components
        .as_ref()
        .map(|components| components.accounts_lt_hash_checksum.clone())
        .unwrap_or_else(|| "unavailable".to_string());

    let changed_accounts = get_changed_accounts(initial_accounts, bank);

    let slot_details = SlotDetails {
        slot,
        bank_hash: bank.hash().to_string(),
        bank_hash_components: Some(BankHashComponents {
            parent_bank_hash: bank.parent_hash().to_string(),
            signature_count: bank.signature_count(),
            last_blockhash: bank.last_blockhash().to_string(),
            accounts_lt_hash_checksum,
            accounts: AccountsDetails {
                accounts: changed_accounts,
            },
        }),
        transactions: Vec::new(),
    };

    Ok(BankHashDetails::new(vec![slot_details]))
}

/// Single-pass mapping during dedup (rotation-compressed).
/// - Build (Pubkey, rotation_idx) entries from the schedule (sampling every 4 slots).
/// - Sort entries by Pubkey bytes for deterministic order.
/// - Dedup in one pass and write mapped indices directly into sched_mapped[rotation_idx].
/// - Hash unique pubkeys and mapped indices into out[0..8] and out[8..16].
///   Returns the number of unique leaders.
pub fn hash_epoch_leaders(
    leader_schedule: &[Pubkey], // per-slot leaders for the whole epoch
    seed: u64,
    out: &mut [u8; 16],
) -> usize {
    // Build composite entries: one per 4-slot rotation
    #[derive(Clone, Copy)]
    struct Entry {
        pk: Pubkey,
        rot_idx: usize,
    }

    let mut entries: Vec<Entry> = leader_schedule
        .iter()
        .step_by(4) // one representative per rotation
        .enumerate()
        .map(|(rot_idx, pk)| Entry { pk: *pk, rot_idx })
        .collect();

    if entries.is_empty() {
        out.fill(0);
        return 0;
    }

    // Sort by pubkey bytes deterministically
    entries.sort_unstable_by(|a, b| a.pk.to_bytes().cmp(&b.pk.to_bytes()));

    // Dedup + write mapping in a single pass
    let rotations = entries.len();
    let mut sched_mapped: Vec<u32> = vec![0u32; rotations];

    let mut uniq_cnt = 0usize;
    let mut prev_bytes: Option<[u8; 32]> = None;

    for e in &entries {
        let bytes = e.pk.to_bytes();
        if prev_bytes != Some(bytes) {
            uniq_cnt = uniq_cnt.saturating_add(1);
            prev_bytes = Some(bytes);
        }
        // uniq index is uniq_cnt - 1
        sched_mapped[e.rot_idx] = uniq_cnt.saturating_sub(1) as u32;
    }

    // Build unique_pubkeys for hashing (exact size = uniq_cnt)
    let mut unique_pubkeys: Vec<Pubkey> = Vec::with_capacity(uniq_cnt);
    prev_bytes = None;
    for e in &entries {
        let bytes = e.pk.to_bytes();
        if prev_bytes != Some(bytes) {
            unique_pubkeys.push(e.pk);
            prev_bytes = Some(bytes);
        }
    }

    // Hash unique pubkeys
    let pub_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            unique_pubkeys.as_ptr() as *const u8,
            unique_pubkeys
                .len()
                .saturating_mul(core::mem::size_of::<Pubkey>()),
        )
    };
    let h1 = fd_hash(seed, pub_bytes);
    out[0..8].copy_from_slice(&h1.to_le_bytes());

    // Part 2 (last 64 bits): Hash of the compressed schedule (leader indices)
    // This captures the scheduled order of the leaders throughout the epoch
    let sched_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            sched_mapped.as_ptr() as *const u8,
            sched_mapped
                .len()
                .saturating_mul(core::mem::size_of::<u32>()),
        )
    };
    let h2 = fd_hash(seed, sched_bytes);
    out[8..16].copy_from_slice(&h2.to_le_bytes());

    uniq_cnt
}

#[allow(deprecated)]
pub fn execute_block(context: BlockContext) -> Option<BlockEffects> {
    let slot_ctx = context.slot_ctx.unwrap();
    let epoch_ctx = context.epoch_ctx.unwrap();
    let fd_features = epoch_ctx.features.unwrap_or_default();
    let feature_set = FeatureSet::from(&fd_features);
    let current_slot = slot_ctx.slot;
    let parent_slot = slot_ctx.prev_slot;
    let poh = Hash::new_from_array(slot_ctx.poh.clone().try_into().unwrap_or_else(|_| [0u8; 32]));

    /* HACK: Because there are three different schedules and rent instances, we need to find and deserialize
    them from the account states first. Technically these different rent / epoch schedules should be fuzzed,
    but that will be out of scope for this fuzzer. */
    let sysvar_accounts: HashMap<&[u8], &AcctState> = context
        .acct_states
        .iter()
        .filter(|item| item.lamports > 0)
        .map(|item| (item.address.as_slice(), item))
        .collect();
    let rent: Rent = get_sysvar(&sysvar_accounts, solana_sysvar::rent::id().as_ref());
    let epoch_schedule: EpochSchedule = get_sysvar(
        &sysvar_accounts,
        solana_sysvar::epoch_schedule::id().as_ref(),
    );
    let recent_blockhashes: RecentBlockhashes = get_sysvar(
        &sysvar_accounts,
        solana_sysvar::recent_blockhashes::id().as_ref(),
    );
    let stake_history: StakeHistory = get_sysvar(&sysvar_accounts, stake_history::id().as_ref());

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
        let blockhash_hash = Hash::new_from_array(blockhash.clone().try_into().unwrap_or_else(|_| [0u8; 32]));
        blockhash_queue.register_hash(&blockhash_hash, lamports_per_signature);
    });

    let mut ancestors = AncestorsForSerialization::default();
    ancestors.insert(current_slot.saturating_sub(1), 1);
    ancestors.insert(current_slot, 1);

    /* Accounts DB config and initialization. Agave v3.1 uses a new Accounts
    interface, which is not compatible with the old one. */
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit_mb: IndexLimitMb::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = AccountsDbConfig {
        index,
        storage_access: StorageAccess::File,
        skip_initial_hash_calc: true,
        ..AccountsDbConfig::default()
    };
    let accounts_db = AccountsDb::new_with_config(
        vec![],
        accounts_db_config.clone(),
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

    let storage_slot = slot_ctx.prev_slot;
    accounts.store_accounts_seq((storage_slot, &accounts_to_store[..]), None);
    // Add the root slot to the accounts DB
    // Now needed when calling Bank::new_from_snapshot() in Agave v3.1
    accounts.accounts_db.add_root(storage_slot);
    let accounts_data_size_initial: u64 = accounts_to_store
        .iter()
        .map(|(_, account)| account.data().len() as u64)
        .sum();

    /* Build the stakes separately */
    let current_epoch = epoch_schedule.get_epoch(current_slot);
    let parent_epoch = epoch_schedule.get_epoch(parent_slot);
    let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(current_slot);
    let stakes_t =
        build_latest_stake_delegations(&context.acct_states, parent_epoch, &stake_history)?;
    let stakes_t_1 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_1)?;
    let stakes_t_2 = build_prev_stake_delegations(&epoch_ctx.vote_accounts_t_2)?;

    let mut epoch_stakes: HashMap<Epoch, VersionedEpochStakes> = HashMap::new();

    /* Add stakes for current_epoch to ensure epoch stakes lookups during
       recalculate_partitioned_rewards don't panic */
    let stakes_t_accounts = Stakes::new(&stakes_t, |pubkey| {
        context.acct_states
            .iter()
            .find(|acct| acct.address.as_slice() == pubkey.as_ref())
            .map(|acct| AccountSharedData::from(acct))
    }).unwrap();
    epoch_stakes.insert(
        current_epoch,
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_accounts),
            current_epoch,
        ),
    );

    epoch_stakes.insert(
        leader_schedule_epoch.saturating_sub(1),
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_2),
            leader_schedule_epoch.saturating_sub(1),
        ),
    );
    epoch_stakes.insert(
        leader_schedule_epoch,
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_1.clone()),
            leader_schedule_epoch,
        ),
    );

    let fee_rate_governor = slot_ctx.fee_rate_governor.unwrap();

    let mut parent_lthash = LtHash::identity();
    for (i, chunk) in slot_ctx.parent_lthash.chunks_exact(2).enumerate() {
        parent_lthash.0[i] = u16::from_le_bytes(chunk.try_into().unwrap());
    }

    // Clone epoch_schedule for later use since it will be moved into bank_fields
    let epoch_schedule_for_effects: EpochSchedule = epoch_schedule.clone();

    let bank_fields = BankFieldsToDeserialize {
        blockhash_queue,
        ancestors,
        hash: Hash::default(),
        parent_hash: Hash::new_from_array(slot_ctx.parent_bank_hash.try_into().unwrap_or_else(|_| [0u8; 32])),
        parent_slot: slot_ctx.prev_slot,
        hard_forks: HardForks::default(),
        transaction_count: 0,
        hashes_per_tick: None,
        capitalization: slot_ctx.prev_epoch_capitalization,
        signature_count: 0,
        tick_height: 64u64.saturating_mul(current_slot),
        max_tick_height: 64u64.saturating_mul(current_slot.saturating_add(1)),
        ticks_per_slot: 64u64,
        ns_per_slot: genesis_config.ns_per_slot(),
        genesis_creation_time: epoch_ctx.genesis_creation_time as i64,
        slots_per_year: genesis_config.slots_per_year(),
        slot: current_slot,
        epoch: current_epoch,
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
            epoch: epoch_schedule.get_epoch(parent_slot),
            epoch_schedule: epoch_schedule.clone(),
            slots_per_year: genesis_config.slots_per_year(),
            rent,
        },
        epoch_schedule,
        inflation: epoch_ctx.inflation.unwrap().into(),
        stakes: stakes_t,
        versioned_epoch_stakes: epoch_stakes,
        is_delta: false,
        accounts_data_len: 0,
        accounts_lt_hash: AccountsLtHash(parent_lthash),
        bank_hash_stats: BankHashStats::default(),
    };

    let bank_rc = BankRc::new(accounts);
    let mut bank = Bank::new_from_snapshot(
        bank_rc,
        &genesis_config,
        Arc::new(RuntimeConfig::default()),
        bank_fields,
        None,
        accounts_data_size_initial, // precomputed above
        Some(feature_set),
    );

    // Store the accounts in the bank using the new interface.
    for (pubkey, account_data) in &accounts_to_store {
        if account_data.lamports() > 0 {
            bank.store_account(pubkey, account_data);
        }
    }

    let leader_schedule = LeaderScheduleCache::new_from_bank(&bank);
    let leader = leader_schedule
        .slot_leader_at(current_slot, Some(&bank))
        .unwrap_or_default();
    bank.set_collector_id_for_tests(leader);

    /* Have we crossed an epoch boundary? */
    if parent_epoch < current_epoch {
        bank.process_new_epoch(
            parent_epoch,
            parent_slot,
            bank.block_height(),
            null_tracer(),
        );
    }
    let l_sched = leader_schedule_utils::leader_schedule(current_epoch, &bank).unwrap();

    bank.distribute_partitioned_epoch_rewards();

    bank.get_transaction_processor().reset_sysvar_cache();

    bank.update_slot_hashes();
    bank.update_stake_history(Some(parent_epoch));
    bank.update_clock(Some(parent_epoch));
    bank.update_last_restart_slot();
    bank.update_recent_blockhashes();
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(&bank);

    /* See this comment to understand why we need to populate the lthash
    cache before executing:
    https://github.com/anza-xyz/agave/blob/v3.0.3/runtime/src/bank.rs#L1409-L1423

    Ideally, caches shouldn't have consensus-relevant effects, and a
    cache miss would just result in a slow fetch insteead of an
    outright divergence... */
    let accounts_modified_this_slot = bank
        .rc
        .accounts
        .accounts_db
        .get_pubkeys_for_slot(current_slot);
    for pubkey in accounts_modified_this_slot {
        bank.cache_for_accounts_lt_hash
            .entry(pubkey)
            .or_insert(AccountsLtHashCacheValue::BankNew);
    }

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
                            <Vec<u8> as TryInto<[u8; 64]>>::try_into(item.clone()).unwrap_or_else(
                                |_| [0u8; 64]
                            ),
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
        let details = create_changed_accounts_bank_hash_details(
            bank_forks.read().unwrap().working_bank().as_ref(),
            &context.acct_states,
        )
        .unwrap();

        let parent_dir: PathBuf = std::env::var("AGAVE_SOLCAP_DIR").unwrap().into();
        let path = parent_dir.join(details.filename().unwrap());
        _ = std::fs::create_dir_all(parent_dir);
        let file = std::fs::File::create(&path).unwrap();
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &details).unwrap();
    }

    // Build leader_schedule_effects for consensus verification:

    // The leader schedule determines which validator is allowed to produce blocks
    // for each slot in an epoch. This section computes metadata and a hash of the
    // schedule to enable cross-implementation verification (e.g., Agave vs Firedancer).

    // Calculate the epoch boundaries:
    // - leader_schedule_epoch: The epoch for which the leader schedule applies
    // - first_slot: The absolute slot number where this epoch begins
    // - slots_in_epoch: Total number of slots in this epoch (can vary by epoch)
    let first_slot = epoch_schedule_for_effects.get_first_slot_in_epoch(current_epoch);
    let slots_in_epoch = epoch_schedule_for_effects.get_slots_in_epoch(current_epoch);

    // Attempt to retrieve the leader schedule for this epoch from the cache

    // Schedule found, obtain effects and hash
    // Generate a deterministic 128-bit hash of the entire leader schedule
    // This hash encodes both WHO the leaders are and WHEN they lead.
    // We use a fixed seed for reproducibility across implementations.
    let mut schedule_hash = [0u8; 16];
    let schedule_pubkeys: Vec<Pubkey> = (0..slots_in_epoch)
        .map(|slot_offset| l_sched[slot_offset])
        .collect();

    let unique_cnt = hash_epoch_leaders(
        &schedule_pubkeys,
        LEADER_SCHEDULE_HASH_SEED,
        &mut schedule_hash,
    );

    // Package all the schedule metadata for output
    let leader_schedule_effects = proto::LeaderScheduleEffects {
        leaders_epoch: current_epoch, // Which epoch this schedule applies to
        leaders_slot0: first_slot,    // First absolute slot in this epoch
        leaders_slot_cnt: slots_in_epoch as u64, // Total slots in this epoch
        leader_pub_cnt: unique_cnt as u64, // Number of unique leader validators
        leaders_sched_cnt: slots_in_epoch as u64, // Number of scheduled leader slots (verification field)
        leader_schedule_hash: schedule_hash.to_vec(), // 128-bit fingerprint of the schedule
    };

    let bank_hash = if result.is_err() {
        Hash::default()
    } else {
        no_schedule_bank.hash()
    };

    let capitalization = if result.is_err() {
        0
    } else {
        no_schedule_bank.capitalization()
    };

    // Then include in the output
    Some(BlockEffects {
        has_error: result.is_err(),
        slot_capitalization: capitalization,
        bank_hash: bank_hash.to_bytes().to_vec(),
        cost_tracker: Some(proto::CostTracker {
            block_cost: cost_tracker.block_cost(),
            vote_cost: cost_tracker.vote_cost(),
        }),
        leader_schedule: Some(leader_schedule_effects),
    })
}
