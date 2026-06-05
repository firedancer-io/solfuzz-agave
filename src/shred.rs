//! Differential shred-parse harness: drives Agave's Blockstore pipeline
//! (pre-filter -> parse -> FEC/recovery -> deshred -> tick verify) and emits
//! ShredParseEffects to diff against Firedancer. Signature and PoH checks are
//! not run; the fuzzer re-proofs each FEC set, so Merkle roots derive normally
//! from the shred bytes.

use crate::utils::create_accounts_db;
use agave_feature_set::{
    discard_unexpected_data_complete_shreds, validate_chained_block_id,
    validate_chained_block_id_2, FeatureSet,
};
use agave_votor_messages::migration::MigrationStatus;
use crossbeam_channel::unbounded;
use prost::Message;
use protosol::protos::{BlockParseResult, FecSetParseResult, ShredParseContext, ShredParseEffects};
use solana_account::AccountSharedData;
use solana_accounts_db::{
    accounts_hash::AccountsLtHash, ancestors::Ancestors, blockhash_queue::BlockhashQueue,
};
use solana_clock::{Epoch, Slot};
use solana_core::window_service::check_duplicate_shred;
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo};
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_keypair::{Keypair, Signer};
use solana_lattice_hash::lt_hash::LtHash;
use solana_ledger::{
    blockstore::{Blockstore, BlockstoreInsertionMetrics, PossibleDuplicateShred},
    blockstore_processor::verify_ticks,
    get_tmp_ledger_path_auto_delete,
    shred::{
        filter::{ShredFilterContext, ShredRecoveryContext},
        layout, Payload, ReedSolomonCache, Shred,
    },
};
use solana_net_utils::SocketAddrSpace;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_runtime::{
    bank::{Bank, BankFieldsToDeserialize, BankHashStats, BankRc},
    bank_forks::BankForks,
    epoch_stakes::VersionedEpochStakes,
    stake_history::StakeHistory,
    stakes::{DeserializableStakes, SerdeStakesToStakeFormat, Stakes},
};
use solana_sdk_ids::sysvar;
use solana_stake_interface::state::Stake;
use solana_streamer::evicting_sender::EvictingSender;
use solana_vote::vote_account::VoteAccounts;
use std::collections::HashMap;
use std::os::raw::c_int;
use std::sync::Arc;
use std::{borrow::Cow, collections::BTreeMap};

/// # Safety
/// Pointers must be valid for the given sizes (solfuzz C ABI).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_shred_parse_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(context) = ShredParseContext::decode(&in_slice[..in_sz as usize]) else {
        return 0;
    };

    let effects = execute_shred_parse(&context);

    let out_psz_val = unsafe { *out_psz } as usize;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_psz_val) };
    let out_vec = effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe {
        *out_psz = out_vec.len() as u64;
    }
    1
}

/// Bank ticks-per-slot, so verify_ticks' tick-count check matches mainnet.
const TICKS_PER_SLOT: u64 = 64;

/// Fixed FEC shape: 32 data + 32 coding (matches FD's reconstructed counts).
const FEC_DATA_SHREDS: usize = 32;
const FEC_CODING_SHREDS: u32 = 32;

pub fn execute_shred_parse(ctx: &ShredParseContext) -> ShredParseEffects {
    let shred_version = ctx.shred_version as u16;
    let root_slot: Slot = ctx.root_slot;
    let discard = ctx
        .features
        .as_ref()
        .map(|f| f.discard_unexpected_data_complete_shreds)
        .unwrap_or(false);

    let mut effects = ShredParseEffects {
        block_parse_result: BlockParseResult::Accepted as i32,
        shred_results: Vec::with_capacity(ctx.shreds.len()),
        fec_set_results: Vec::new(),
    };

    // Bank at the root slot: drives the filter/recovery slot bounds, verify_ticks
    // tick params, and the dup feature gate.
    // FD: resolver + sched config (shred_version, advance_slot_old(root_slot), discard feature).
    let mut feature_set = FeatureSet::default();

    // FD assumes these features to always be active
    feature_set.activate(&validate_chained_block_id::id(), 0);
    feature_set.activate(&validate_chained_block_id_2::id(), 0);

    if discard {
        feature_set.activate(&discard_unexpected_data_complete_shreds::id(), 0);
    }
    let bank = build_root_bank(root_slot, feature_set);
    let migration = MigrationStatus::default();

    // Step 1: parse each shred; record whether it's a chained Merkle shred.
    // FD: fd_shred_parse + fd_shred_is_chained. should_discard_shred only gates accumulation.
    let mut filter = ShredFilterContext::new(bank.clone(), shred_version);
    let mut parsed: Vec<Shred> = Vec::with_capacity(ctx.shreds.len());
    for entry in &ctx.shreds {
        let payload = entry.as_slice();
        let parsed_shred = Shred::new_from_serialized_shred(entry.clone()).ok();
        let parses_as_chained = parsed_shred
            .as_ref()
            .is_some_and(|s| s.chained_merkle_root().is_ok());
        effects.shred_results.push(parses_as_chained);
        if !filter.should_discard_shred(payload) {
            if let Some(shred) = parsed_shred {
                parsed.push(shred);
            }
        }
    }

    // Throwaway gossip/consensus sinks for the shared duplicate handler.
    // FD: dedup is internal to fd_fec_resolver (no separate sink).
    let keypair = Keypair::new();
    let cluster_info = ClusterInfo::new(
        ContactInfo::new_localhost(&keypair.pubkey(), 0),
        Arc::new(keypair),
        SocketAddrSpace::Unspecified,
    );
    let (dup_slots_sender, _dup_slots_rx) = unbounded::<Slot>();

    // FEC accumulate / recover / dedup in an ephemeral blockstore.
    // FD: fd_fec_resolver_add_shred.
    let ledger_path = get_tmp_ledger_path_auto_delete!();
    let blockstore = Blockstore::open(ledger_path.path()).expect("blockstore open");
    let (retransmit_sender, _retransmit_rx) = EvictingSender::<Vec<Payload>>::new_bounded(0);
    let mut recovery = ShredRecoveryContext::new(
        ReedSolomonCache::default(),
        retransmit_sender,
        bank.clone(),
        shred_version,
    );
    let mut metrics = BlockstoreInsertionMetrics::default();
    let handle_duplicate = |dup: PossibleDuplicateShred| {
        let _ = check_duplicate_shred(
            &cluster_info,
            &blockstore,
            &dup_slots_sender,
            dup,
            true, // hardcoded-on to match Firedancer assumptions
            true, // hardcoded-on to match Firedancer assumptions
        );
    };
    let shreds_iter = parsed
        .iter()
        .map(|s| (Cow::Borrowed(s), /*is_repaired:*/ false));
    let _ = blockstore.insert_shreds_handle_duplicate(
        shreds_iter,
        None,
        false, // is_trusted: keep dedup + integrity checks
        &mut recovery,
        &handle_duplicate,
        &mut metrics,
    );

    let mut slots: Vec<Slot> = parsed.iter().map(|s| s.slot()).collect();
    slots.sort_unstable();
    slots.dedup();

    // Deshred + tick verify per slot (PoH intentionally not run).
    // FD: fd_sched_fec_ingest (PoH verify bypassed).
    for &slot in &slots {
        let (entries, _num_shreds, is_full) = blockstore
            .get_slot_entries_with_shred_info(slot, 0, false)
            .unwrap_or((Vec::new(), 0, false));
        if entries.is_empty() {
            continue;
        }
        let mut tick_hash_count = 0u64;
        if verify_ticks(&bank, &entries, is_full, &mut tick_hash_count, &migration).is_err() {
            effects.block_parse_result = BlockParseResult::RejectedInvalidHeader as i32;
        }
    }

    // Emit one result per completed FEC set.
    // FD: capture_completed_fec + reasm pop -> fec_set_results.
    for &slot in &slots {
        let data_shreds = blockstore
            .get_data_shreds_for_slot(slot, 0)
            .unwrap_or_default();
        let mut by_fec: BTreeMap<u32, Vec<Shred>> = BTreeMap::new();
        for s in data_shreds {
            by_fec.entry(s.fec_set_index()).or_default().push(s);
        }
        for (fec_set_index, mut group) in by_fec {
            // Emit only complete data sets (32 shreds), matching FD's
            // completion-gated emission; partial/inconsistent sets are skipped.
            if group.len() != FEC_DATA_SHREDS {
                continue;
            }
            group.sort_unstable_by_key(|s| s.index());
            let first = &group[0];
            let parent = first.parent().unwrap_or(slot);
            // FD: fd_shred_merkle_root(base_data), derived from the proof bytes.
            let merkle_root = first
                .merkle_root()
                .map(|h| h.to_bytes().to_vec())
                .unwrap_or_default();
            let chained_merkle_root = first
                .chained_merkle_root()
                .map(|h| h.to_bytes().to_vec())
                .unwrap_or_default();
            // Concatenate each data shred's data region (matches FD; not deshred,
            // which requires the set to end on a DATA_COMPLETE boundary).
            let mut payload = Vec::new();
            for s in &group {
                if let Ok(data) = layout::get_data(s.payload()) {
                    payload.extend_from_slice(data);
                }
            }
            effects.fec_set_results.push(FecSetParseResult {
                completed: true,
                merkle_root,
                chained_merkle_root,
                payload,
                slot,
                fec_set_index,
                parent_offset: slot.saturating_sub(parent) as u32,
                shred_version: ctx.shred_version,
                num_data_shreds: group.len() as u32,
                // FD reconstructs + reports 32 coding; mirror that fixed count.
                num_coding_shreds: FEC_CODING_SHREDS,
            });
        }
    }

    effects
}

/// Minimal bank at `root_slot` with the caller-provided `feature_set`: supplies
/// the filter/recovery slot bounds, verify_ticks tick params (one slot of ticks,
/// PoH off), and the dup feature gate. Only the rent sysvar is stored, which
/// new_for_txn_tests requires.
fn build_root_bank(root_slot: Slot, feature_set: FeatureSet) -> Arc<Bank> {
    let epoch_schedule = EpochSchedule::default();
    let epoch = epoch_schedule.get_epoch(root_slot);
    let parent_slot = root_slot.saturating_sub(1);

    let accounts = create_accounts_db(vec![]);
    let rent_account = AccountSharedData::new_data(1, &Rent::default(), &sysvar::id()).unwrap();
    accounts.store_accounts_seq(
        (parent_slot, &[(sysvar::rent::id(), rent_account)][..]),
        None,
        &Ancestors::default(),
    );
    accounts.accounts_db.add_root(parent_slot);
    let bank_rc = BankRc::new(accounts);

    let stakes = DeserializableStakes {
        vote_accounts: VoteAccounts::default(),
        stake_delegations: vec![],
        unused: 0,
        epoch,
        stake_history: StakeHistory::default(),
    };
    let mut epoch_stakes: HashMap<Epoch, VersionedEpochStakes> = HashMap::new();
    for key in [epoch, epoch.saturating_add(1)] {
        epoch_stakes.insert(
            key,
            VersionedEpochStakes::new(
                SerdeStakesToStakeFormat::Stake(Stakes::<Stake>::default()),
                key,
            ),
        );
    }

    let fields = BankFieldsToDeserialize {
        blockhash_queue: BlockhashQueue::default(),
        hash: Hash::default(),
        parent_hash: Hash::default(),
        parent_slot,
        hard_forks: HardForks::default(),
        transaction_count: 0,
        tick_height: TICKS_PER_SLOT.saturating_mul(root_slot),
        signature_count: 0,
        capitalization: 0,
        max_tick_height: TICKS_PER_SLOT.saturating_mul(root_slot.saturating_add(1)),
        hashes_per_tick: None,
        ticks_per_slot: TICKS_PER_SLOT,
        ns_per_slot: 0,
        genesis_creation_time: 0,
        slots_per_year: 0.0,
        slot: root_slot,
        block_height: root_slot,
        leader_id: Pubkey::default(),
        fee_rate_governor: FeeRateGovernor::default(),
        epoch_schedule,
        inflation: Inflation::default(),
        stakes,
        versioned_epoch_stakes: vec![],
        is_delta: false,
        accounts_data_len: 0,
        accounts_lt_hash: AccountsLtHash(LtHash::identity()),
        bank_hash_stats: BankHashStats::default(),
        block_id: None,
    };

    let bank = Bank::new_for_txn_tests(bank_rc, fields, feature_set, epoch_stakes);
    BankForks::new_rw_arc(bank).read().unwrap().root_bank()
}
