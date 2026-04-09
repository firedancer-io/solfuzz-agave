use crate::utils::fd_hash::fd_hash;
use crate::utils::program::common::{build_versioned_message, get_sysvar};
use crate::utils::{
    compute_accounts_data_size, create_accounts_db, deserialize_accounts, feature_set_from_protos,
    restore_blockhash_queue,
};
use agave_votor_messages::migration::MigrationStatus;
use prost::Message;
use protosol::protos::{self, AcctState};
use protosol::protos::{BlockContext, BlockEffects};
#[allow(deprecated)]
use solana_account::{AccountSharedData, ReadableAccount};
use solana_accounts_db::accounts_hash::AccountsLtHash;
use solana_clock::{Epoch, NUM_CONSECUTIVE_LEADER_SLOTS};
use solana_entry::entry::Entry;
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_lattice_hash::lt_hash::LtHash;
use solana_leader_schedule::LeaderSchedule;
use solana_ledger::blockstore_processor::{
    confirm_slot_entries, create_thread_pool, ConfirmationProgress, ConfirmationTiming,
};
use solana_pubkey::Pubkey;
use solana_runtime::bank::bank_hash_details::{
    AccountsDetails, BankHashComponents, BankHashDetails, SlotDetails,
};
use solana_runtime::bank::{Bank, BankFieldsToDeserialize, BankHashStats, BankRc};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_runtime::installed_scheduler_pool::BankWithScheduler;
use solana_runtime::prioritization_fee_cache::PrioritizationFeeCache;
use solana_runtime::stake_account;
use solana_runtime::stake_history::StakeHistory;
use solana_runtime::stakes::{DeserializableStakes, SerdeStakesToStakeFormat, Stakes};
use solana_sdk_ids::sysvar::stake_history;
use solana_signature::Signature;
use solana_stake_interface::state::Delegation;
use solana_transaction::versioned::VersionedTransaction;
use solana_vote::vote_account::{VoteAccount, VoteAccounts};
use solana_vote_interface::state::{VoteState1_14_11, VoteStateV3, VoteStateV4, VoteStateVersions};
use std::collections::HashMap;
use std::ffi::c_int;
use std::path::PathBuf;

// Firedancer-compatible seed for leader schedule hashing
const LEADER_SCHEDULE_HASH_SEED: u64 = 0xDEADFACE;
const TICKS_PER_SLOT: u64 = 64;
const SECONDS_PER_YEAR: f64 = 365.242199 * 24.0 * 60.0 * 60.0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_block_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(block_context) = BlockContext::decode(&in_slice[..in_sz as usize]) else {
        return 0;
    };

    let Some(block_result) = execute_block(block_context) else {
        return 0;
    };

    let out_psz_val = unsafe { *out_psz } as usize;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_psz_val) };
    let out_vec = block_result.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }

    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };

    1
}

/* This is a little bit hacky because there's no direct Agave API that gets us a populated Stakes<Delegation> object
from a set of account states. Fine, I'll do it myself... */
fn build_latest_stake_delegations(
    account_states: &[protos::AcctState],
    epoch: Epoch,
    stake_history: &StakeHistory,
) -> DeserializableStakes<Delegation> {
    // let mut stakes = Stakes::<Delegation>::default();
    let mut stakes = DeserializableStakes::<Delegation> {
        vote_accounts: VoteAccounts::default(),
        stake_delegations: account_states
            .iter()
            .filter(|item| item.lamports > 0)
            .filter_map(|account_state| {
                let pubkey =
                    Pubkey::new_from_array(account_state.address.clone().try_into().unwrap());
                let account_shared_data = AccountSharedData::from(account_state);
                if let Ok(stake_account) =
                    stake_account::StakeAccount::<Delegation>::try_from(account_shared_data)
                {
                    /* Skip nonzero delegations */
                    if stake_account.delegation().stake > 0 {
                        return Some((pubkey, *stake_account.delegation()));
                    }
                }
                None
            })
            .collect(),
        unused: 0,
        epoch,
        stake_history: stake_history.clone(),
    };

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
                        .iter()
                        .filter_map(|(_, delegation)| {
                            if delegation.voter_pubkey == pubkey {
                                Some(delegation.stake(epoch, stake_history, Some(0)))
                            } else {
                                None
                            }
                        })
                        .sum()
                });
            }
        });

    stakes
}

fn synthesize_vote_account(pva: &protos::PrevVoteAccount) -> (Pubkey, u64, VoteAccount) {
    let vote_pubkey = Pubkey::new_from_array(pva.address.clone().try_into().unwrap());
    let node_pk = Pubkey::new_from_array(pva.node_pubkey.clone().try_into().unwrap());

    let epoch_credits: Vec<(Epoch, u64, u64)> = pva
        .epoch_credits
        .iter()
        .map(|ec| (ec.epoch, ec.credits, ec.prev_credits))
        .collect();

    let versioned = match pva.version() {
        protos::VoteAccountVersion::V11411 => {
            VoteStateVersions::V1_14_11(Box::new(VoteState1_14_11 {
                node_pubkey: node_pk,
                commission: pva.commission as u8,
                epoch_credits,
                ..VoteState1_14_11::default()
            }))
        }
        protos::VoteAccountVersion::V3 => VoteStateVersions::new_v3(VoteStateV3 {
            node_pubkey: node_pk,
            commission: pva.commission as u8,
            epoch_credits,
            ..VoteStateV3::default()
        }),
        protos::VoteAccountVersion::V4 => VoteStateVersions::new_v4(VoteStateV4 {
            node_pubkey: node_pk,
            inflation_rewards_commission_bps: (pva.commission as u16) * 100,
            epoch_credits,
            ..VoteStateV4::default()
        }),
    };

    let serialized = bincode::serialize(&versioned).unwrap();
    let mut account = AccountSharedData::new(1, serialized.len(), &solana_sdk_ids::vote::id());
    account.set_data_from_slice(&serialized);

    let vote_account = VoteAccount::try_from(account).unwrap();
    (vote_pubkey, pva.stake, vote_account)
}

/* Build stake delegations for previous epochs. The difference between this and `build_latest_stake_delegations()` is that
we use the provided votes cache instead of the latest input account states. */
#[allow(deprecated)]
fn build_prev_epoch_stakes(
    vote_accounts: &[protos::PrevVoteAccount],
) -> Stakes<stake_account::StakeAccount<Delegation>> {
    let stakes = DeserializableStakes::<Delegation> {
        vote_accounts: vote_accounts
            .iter()
            .fold(VoteAccounts::default(), |mut acc, pva| {
                let (pubkey, stake, vote_account) = synthesize_vote_account(pva);
                acc.insert(pubkey, vote_account, || stake);
                acc
            }),
        stake_delegations: Vec::default(),
        unused: 0,
        epoch: Epoch::default(),
        stake_history: StakeHistory::default(),
    };

    Stakes::load_from_deserialized_delegations(stakes.clone(), |pubkey| {
        stakes
            .vote_accounts
            .get(pubkey)
            .map(|vote_account| vote_account.account().clone())
    })
    .unwrap()
}

fn get_changed_accounts(
    initial_accounts: &[protos::AcctState],
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
    initial_accounts: &[protos::AcctState],
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
    let bank_ctx = context.bank.unwrap();
    let fd_features = bank_ctx.features.unwrap_or_default();
    let feature_set = feature_set_from_protos(&fd_features);

    let current_slot = bank_ctx.slot;
    let parent_slot = bank_ctx.parent_slot;
    let poh = Hash::new_from_array(bank_ctx.poh.clone().try_into().unwrap());

    let epoch_schedule: EpochSchedule = bank_ctx.epoch_schedule.as_ref().unwrap().into();

    let sysvar_accounts: HashMap<&[u8], &AcctState> = context
        .acct_states
        .iter()
        .filter(|item| item.lamports > 0)
        .map(|item| (item.address.as_slice(), item))
        .collect();
    let stake_history: StakeHistory = get_sysvar(&sysvar_accounts, stake_history::id().as_ref());

    let lamports_per_signature = bank_ctx.rbh_lamports_per_signature as u64;

    let blockhash_queue = restore_blockhash_queue(&bank_ctx.blockhash_queue);

    /* Accounts DB config and initialization */
    let accounts = create_accounts_db(vec![]);
    let accounts_to_store = deserialize_accounts(&context.acct_states);

    accounts.store_accounts_seq((parent_slot, &accounts_to_store[..]), None, None);
    accounts.accounts_db.add_root(parent_slot);
    let accounts_data_size_initial = compute_accounts_data_size(&accounts_to_store);

    /* Build the stakes separately */
    let current_epoch = epoch_schedule.get_epoch(current_slot);
    let parent_epoch = epoch_schedule.get_epoch(parent_slot);
    let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(parent_slot);

    let stakes_t =
        build_latest_stake_delegations(&context.acct_states, parent_epoch, &stake_history);

    // Convert stakes_t (current epoch delegations + stake_history from sysvar) into
    // Stakes<StakeAccount> for the StakesCache. This mirrors new_from_snapshot which
    // loads the StakesCache from the deserialized snapshot stakes.
    let stakes_for_cache = Stakes::load_from_deserialized_delegations(stakes_t.clone(), |pubkey| {
        accounts_to_store
            .iter()
            .find(|(pk, _)| pk == pubkey)
            .map(|(_, acct)| acct.clone())
    })
    .unwrap();

    let stakes_t_1 = build_prev_epoch_stakes(&bank_ctx.vote_accounts_t_1);
    let stakes_t_2 = build_prev_epoch_stakes(&bank_ctx.vote_accounts_t_2);

    let current_epoch_stakes = VersionedEpochStakes::new(
        SerdeStakesToStakeFormat::from(stakes_t_2),
        leader_schedule_epoch.saturating_sub(1),
    );

    let l_sched = LeaderSchedule::new(
        current_epoch_stakes.stakes().vote_accounts().as_ref(),
        current_epoch,
        epoch_schedule.get_slots_in_epoch(current_epoch),
        NUM_CONSECUTIVE_LEADER_SLOTS,
    );
    let (_, slot_index) = epoch_schedule.get_epoch_and_slot_index(current_slot);
    let leader = l_sched[slot_index];

    let mut epoch_stakes: HashMap<Epoch, VersionedEpochStakes> = HashMap::new();
    epoch_stakes.insert(
        leader_schedule_epoch.saturating_sub(1),
        current_epoch_stakes,
    );
    epoch_stakes.insert(
        leader_schedule_epoch,
        VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::from(stakes_t_1.clone()),
            leader_schedule_epoch,
        ),
    );

    let input_fee_rate_governor = bank_ctx.fee_rate_governor.as_ref().unwrap();
    let fee_rate_governor = FeeRateGovernor::new_derived(
        &FeeRateGovernor {
            lamports_per_signature,
            target_lamports_per_signature: input_fee_rate_governor.target_lamports_per_signature,
            target_signatures_per_slot: input_fee_rate_governor.target_signatures_per_slot,
            min_lamports_per_signature: input_fee_rate_governor.min_lamports_per_signature,
            max_lamports_per_signature: input_fee_rate_governor.max_lamports_per_signature,
            burn_percent: input_fee_rate_governor.burn_percent as u8,
        },
        bank_ctx.parent_signature_count,
    );

    let mut parent_lthash = LtHash::identity();
    for (i, chunk) in bank_ctx.parent_lt_hash.chunks_exact(2).enumerate() {
        parent_lthash.0[i] = u16::from_le_bytes(chunk.try_into().unwrap());
    }

    assert!(bank_ctx.ns_per_slot.len() == 16);
    let ns_per_slot = u128::from_le_bytes(bank_ctx.ns_per_slot[..16].try_into().unwrap());
    let slots_per_year = SECONDS_PER_YEAR * 1e9 / ns_per_slot as f64;
    // Clone epoch_schedule for later use since it will be moved into bank_fields
    let epoch_schedule_for_effects = epoch_schedule.clone();

    let bank_fields = BankFieldsToDeserialize {
        blockhash_queue,
        hash: Hash::default(),
        parent_hash: Hash::new_from_array(bank_ctx.parent_bank_hash.try_into().unwrap()),
        parent_slot,
        hard_forks: HardForks::default(),
        transaction_count: 0,
        hashes_per_tick: None,
        capitalization: bank_ctx.capitalization,
        signature_count: 0,
        tick_height: TICKS_PER_SLOT.saturating_mul(current_slot),
        max_tick_height: TICKS_PER_SLOT.saturating_mul(current_slot.saturating_add(1)),
        ticks_per_slot: TICKS_PER_SLOT,
        ns_per_slot,
        genesis_creation_time: 0,
        slots_per_year,
        slot: current_slot,
        block_height: bank_ctx.block_height,
        leader_id: leader.id,
        fee_rate_governor,
        epoch_schedule,
        inflation: bank_ctx.inflation.unwrap().into(),
        stakes: stakes_t,
        versioned_epoch_stakes: vec![],
        is_delta: false,
        accounts_data_len: 0,
        accounts_lt_hash: AccountsLtHash(parent_lthash),
        bank_hash_stats: BankHashStats::default(),
    };

    let bank_rc = BankRc::new(accounts);
    let mut bank = Bank::new_for_block_fuzzing(
        bank_rc,
        bank_fields,
        feature_set,
        epoch_stakes,
        stakes_for_cache,
        accounts_data_size_initial,
    );

    // Store the accounts in the bank. Must happen before prepare_for_block_execution
    // so that sysvar updates and epoch processing operate on the correct base state.
    for (pubkey, account_data) in &accounts_to_store {
        if account_data.lamports() > 0 {
            bank.store_account(pubkey, account_data);
        }
    }

    // Complete initialization: epoch processing, sysvar updates, LT hash cache
    bank.prepare_for_block_execution();

    let bank_forks = BankForks::new_rw_arc(bank);
    let bank = bank_forks.write().unwrap().root_bank();

    let tx_entries = context
        .txns
        .iter()
        .map(|txn| {
            let message = build_versioned_message(txn.message.as_ref()?);
            let signatures = txn
                .signatures
                .iter()
                .map(|item| {
                    Signature::from(<Vec<u8> as TryInto<[u8; 64]>>::try_into(item.clone()).unwrap())
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
        .collect::<Option<Vec<Entry>>>()?;

    let mut entries = vec![
        Entry {
            num_hashes: 1,
            hash: poh,
            transactions: vec![],
        };
        63
    ];
    entries.extend(tx_entries);
    entries.push(Entry {
        num_hashes: 1,
        hash: poh,
        transactions: vec![],
    });

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
        None,
        Some(&PrioritizationFeeCache::new(0u64)),
        &MigrationStatus::default(),
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

    // Generate a deterministic 128-bit hash of the entire leader schedule.
    // This hash encodes both WHO the leaders are and WHEN they lead.
    // We use a fixed seed for reproducibility across implementations.
    let mut schedule_hash = [0u8; 16];
    let schedule_pubkeys: Vec<Pubkey> = (0..slots_in_epoch)
        .map(|slot_offset| l_sched[slot_offset].id)
        .collect();

    let unique_cnt = hash_epoch_leaders(
        &schedule_pubkeys,
        LEADER_SCHEDULE_HASH_SEED,
        &mut schedule_hash,
    );

    // Package all the schedule metadata for output
    let leader_schedule_effects = protos::LeaderScheduleEffects {
        leaders_epoch: current_epoch,     // Which epoch this schedule applies to
        leaders_slot0: first_slot,        // First absolute slot in this epoch
        leaders_slot_cnt: slots_in_epoch, // Total slots in this epoch
        leader_pub_cnt: unique_cnt as u64, // Number of unique leader validators
        leaders_sched_cnt: slots_in_epoch, // Number of scheduled leader slots (verification field)
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
        cost_tracker: Some(protos::CostTracker {
            block_cost: cost_tracker.block_cost(),
            vote_cost: cost_tracker.vote_cost(),
        }),
        leader_schedule: Some(leader_schedule_effects),
    })
}
