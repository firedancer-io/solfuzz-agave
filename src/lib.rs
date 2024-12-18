#![allow(clippy::missing_safety_doc)]

pub mod elf_loader;
pub mod pack;
mod shred_parse;
pub mod txn_fuzzer;
pub mod utils;
pub mod vm_cpi_syscall;
pub mod vm_interp;
pub mod vm_syscalls;

use prost::Message;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_log_collector::LogCollector;
use solana_program::hash::Hash;
use solana_program_runtime::invoke_context::EnvironmentConfig;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::loaded_programs::ProgramCacheEntry;
use solana_program_runtime::loaded_programs::ProgramCacheForTxBatch;
use solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_sdk::account::{Account, AccountSharedData, ReadableAccount};
use solana_sdk::clock::Clock;
use solana_sdk::epoch_schedule::EpochSchedule;
use solana_sdk::feature_set::*;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::instruction::{CompiledInstruction, InstructionError};
use solana_sdk::precompiles::{is_precompile, verify_if_precompile};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::rent::Rent;
use solana_sdk::rent_collector::RentCollector;
use solana_sdk::stable_layout::stable_instruction::StableInstruction;
use solana_sdk::stable_layout::stable_vec::StableVec;
use solana_sdk::sysvar::last_restart_slot;
use solana_sdk::sysvar::SysvarId;
use solana_sdk::transaction_context::{
    IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
};
use solana_svm::program_loader;
use solana_timings::ExecuteTimings;

use crate::utils::err_map::instr_err_to_num;
use crate::utils::feature_u64;
use solana_svm::transaction_processing_callback::TransactionProcessingCallback;
use solfuzz_agave_macro::{declare_core_bpf_default_compute_units, load_core_bpf_program};
use std::collections::HashSet;
use std::env;
use std::ffi::c_int;
use std::sync::Arc;
use thiserror::Error;

#[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
use solana_sdk::{
    account::WritableAccount,
    slot_hashes::{SlotHash, SlotHashes},
    sysvar::Sysvar,
};

// macro to rewrite &[IDENTIFIER, ...] to &[feature_u64(IDENTIFIER::id()), ...]
#[macro_export]
macro_rules! feature_list {
    ($($feature:ident),*$(,)?) => {
        &[$(feature_u64(&$feature::id())),*]
    };
}

pub static HARDCODED_FEATURES: &[u64] = feature_list![
    secp256k1_program_enabled,
    spl_token_v2_multisig_fix,
    no_overflow_rent_distribution,
    filter_stake_delegation_accounts,
    require_custodian_for_locked_stake_authorize,
    spl_token_v2_self_transfer_fix,
    check_init_vote_data,
    secp256k1_recover_syscall_enabled,
    system_transfer_zero_check,
    dedupe_config_program_signers,
    verify_tx_signatures_len,
    vote_stake_checked_instructions,
    rent_for_sysvars,
    libsecp256k1_0_5_upgrade_enabled,
    tx_wide_compute_cap,
    spl_token_v2_set_authority_fix,
    merge_nonce_error_into_system_error,
    disable_fees_sysvar,
    stake_merge_with_unmatched_credits_observed,
    versioned_tx_message_enabled,
    libsecp256k1_fail_on_bad_count,
    libsecp256k1_fail_on_bad_count2,
    instructions_sysvar_owned_by_sysvar,
    stake_program_advance_activating_credits_observed,
    credits_auto_rewind,
    demote_program_write_locks,
    ed25519_program_enabled,
    return_data_syscall_enabled,
    reduce_required_deploy_balance,
    sol_log_data_syscall_enabled,
    stakes_remove_delegation_if_inactive,
    do_support_realloc,
    prevent_calling_precompiles_as_programs,
    optimize_epoch_boundary_updates,
    remove_native_loader,
    send_to_tpu_vote_port,
    requestable_heap_size,
    disable_fee_calculator,
    add_compute_budget_program,
    nonce_must_be_writable,
    spl_token_v3_3_0_release,
    leave_nonce_on_success,
    reject_empty_instruction_without_program,
    fixed_memcpy_nonoverlapping_check,
    reject_non_rent_exempt_vote_withdraws,
    evict_invalid_stakes_cache_entries,
    allow_votes_to_directly_update_vote_state,
    max_tx_account_locks,
    require_rent_exempt_accounts,
    filter_votes_outside_slot_hashes,
    update_syscall_base_costs,
    stake_deactivate_delinquent_instruction,
    vote_withdraw_authority_may_change_authorized_voter,
    spl_associated_token_account_v1_0_4,
    reject_vote_account_close_unless_zero_credit_epoch,
    add_get_processed_sibling_instruction_syscall,
    bank_transaction_count_fix,
    disable_bpf_deprecated_load_instructions,
    disable_bpf_unresolved_symbols_at_runtime,
    record_instruction_in_transaction_context_push,
    syscall_saturated_math,
    check_physical_overlapping,
    limit_secp256k1_recovery_id,
    disable_deprecated_loader,
    check_slice_translation_size,
    stake_split_uses_rent_sysvar,
    add_get_minimum_delegation_instruction_to_stake_program,
    error_on_syscall_bpf_function_hash_collisions,
    reject_callx_r10,
    drop_redundant_turbine_path,
    executables_incur_cpi_data_cost,
    fix_recent_blockhashes,
    update_rewards_from_cached_accounts,
    spl_token_v3_4_0,
    spl_associated_token_account_v1_1_0,
    default_units_per_instruction,
    stake_allow_zero_undelegated_amount,
    require_static_program_ids_in_transaction,
    add_set_compute_unit_price_ix,
    include_account_index_in_rent_error,
    add_shred_type_to_shred_seed,
    warp_timestamp_with_a_vengeance,
    separate_nonce_from_blockhash,
    enable_durable_nonce,
    vote_state_update_credit_per_dequeue,
    quick_bail_on_panic,
    nonce_must_be_authorized,
    nonce_must_be_advanceable,
    vote_authorize_with_seed,
    preserve_rent_epoch_for_rent_exempt_accounts,
    enable_early_verification_of_account_modifications,
    prevent_crediting_accounts_that_end_rent_paying,
    cap_bpf_program_instruction_accounts,
    use_default_units_in_fee_calculation,
    compact_vote_state_updates,
    disable_cpi_setting_executable_and_rent_epoch,
    on_load_preserve_rent_epoch_for_rent_exempt_accounts,
    account_hash_ignore_slot,
    set_exempt_rent_epoch_max,
    stop_sibling_instruction_search_at_parent,
    vote_state_update_root_fix,
    cap_accounts_data_allocations_per_transaction,
    epoch_accounts_hash,
    remove_deprecated_request_unit_ix,
    disable_rehash_for_rent_epoch,
    limit_max_instruction_trace_length,
    check_syscall_outputs_do_not_overlap,
    enable_program_redeployment_cooldown,
    move_serialized_len_ptr_in_cpi,
    disable_builtin_loader_ownership_chains,
    cap_transaction_accounts_data_size,
    remove_congestion_multiplier_from_fee_calculation,
    enable_request_heap_frame_ix,
    prevent_rent_paying_rent_recipients,
    delay_visibility_of_program_deployment,
    add_set_tx_loaded_accounts_data_size_instruction,
    round_up_heap_size,
    remove_bpf_loader_incorrect_program_id,
    native_programs_consume_cu,
    stop_truncating_strings_in_syscalls,
    vote_state_add_vote_latency,
    checked_arithmetic_in_fee_validation,
    require_rent_exempt_split_destination,
    validate_fee_collector_account,
    curve25519_restrict_msm_length,
    deprecate_unused_legacy_vote_plumbing,
    simplify_alt_bn128_syscall_error_codes,
    ed25519_precompile_verify_strict,
    migrate_address_lookup_table_program_to_core_bpf,
    migrate_config_program_to_core_bpf,
    get_sysvar_syscall_enabled,
];

static SUPPORTED_FEATURES: &[u64] = feature_list![
    deprecate_rewards_sysvar,
    pico_inflation,
    warp_timestamp_again,
    blake3_syscall_enabled,
    curve25519_syscall_enabled,
    enable_partitioned_epoch_reward,
    stake_raise_minimum_delegation_to_1_sol,
    stake_minimum_delegation_for_rewards,
    disable_deploy_of_alloc_free_syscall,
    enable_bpf_loader_extend_program_ix,
    skip_rent_rewrites,
    loosen_cpi_size_restriction,
    incremental_snapshot_only_incremental_hash_calculation,
    relax_authority_signer_check_for_lookup_table_creation,
    increase_tx_account_lock_limit,
    enable_bpf_loader_set_authority_checked_ix,
    enable_alt_bn128_syscall,
    commission_updates_only_allowed_in_first_half_of_epoch,
    enable_turbine_fanout_experiments,
    disable_turbine_fanout_experiments,
    update_hashes_per_tick,
    enable_big_mod_exp_syscall,
    apply_cost_tracker_during_replay,
    bpf_account_data_direct_mapping,
    switch_to_new_elf_parser,
    include_loaded_accounts_data_size_in_fee_calculation,
    simplify_writable_program_account_check,
    clean_up_delegation_errors,
    last_restart_slot_sysvar,
    reduce_stake_warmup_cooldown,
    enable_poseidon_syscall,
    timely_vote_credits,
    remaining_compute_units_syscall_enabled,
    enable_program_runtime_v2_and_loader_v4,
    better_error_codes_for_tx_lamport_check,
    enable_alt_bn128_compression_syscall,
    update_hashes_per_tick2,
    update_hashes_per_tick3,
    update_hashes_per_tick4,
    update_hashes_per_tick5,
    update_hashes_per_tick6,
    enable_zk_transfer_with_fee,
    drop_legacy_shreds,
    consume_blockstore_duplicate_proofs,
    index_erasure_conflict_duplicate_proofs,
    allow_commission_decrease_at_any_time,
    merkle_conflict_duplicate_proofs,
    disable_bpf_loader_instructions,
    enable_zk_proof_from_account,
    cost_model_requested_write_lock_cost,
    enable_gossip_duplicate_proof_ingestion,
    enable_chained_merkle_shreds,
    remove_rounding_in_fee_calculation,
    enable_tower_sync_ix,
    reward_full_priority_fee,
    disable_rent_fees_collection,
    add_new_reserved_account_keys,
    chained_merkle_conflict_duplicate_proofs,
    abort_on_invalid_curve,
    zk_elgamal_proof_program_enabled,
    move_stake_and_move_lamports_ixs,
    deprecate_legacy_vote_ixs,
    partitioned_epoch_rewards_superfeature,
    enable_secp256r1_precompile,
    migrate_feature_gate_program_to_core_bpf,
    enable_get_epoch_stake_syscall,
    disable_account_loader_special_case,
];

// If the `CORE_BPF_PROGRAM_ID` variable is set, declares the default compute
// units used by the program's builtin version.
//
// This constant is used to stub-out compute unit conformance checks, since the
// BPF version will use different amounts of CUs.
declare_core_bpf_default_compute_units!();

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/org.solana.sealevel.v1.rs"));
}

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("Invalid protobuf")]
    InvalidProtobuf(#[from] prost::DecodeError),

    #[error("Integer out of range")]
    IntegerOutOfRange,

    #[error("Invalid hash bytes")]
    InvalidHashBytes,

    #[error("Invalid public key bytes")]
    InvalidPubkeyBytes,

    #[error("Account missing")]
    AccountMissing,

    #[error("Invalid fixture input")]
    InvalidFixtureInput,

    #[error("Invalid fixture output")]
    InvalidFixtureOutput,
}

pub struct InstrContext {
    pub feature_set: FeatureSet,
    pub accounts: Vec<(Pubkey, Account)>,
    pub instruction: StableInstruction,
    pub cu_avail: u64,
    pub rent_collector: RentCollector,
    pub last_blockhash: Hash,
    pub lamports_per_signature: u64,
}

impl TransactionProcessingCallback for InstrContext {
    fn account_matches_owners(&self, account: &Pubkey, owners: &[Pubkey]) -> Option<usize> {
        let account_shared_data: Vec<(Pubkey, AccountSharedData)> = self
            .accounts
            .iter()
            .map(|(_pubkey, _account)| (*_pubkey, AccountSharedData::from(_account.clone())))
            .collect();
        if let Some(data) = account_shared_data
            .iter()
            .find(|(pubkey, _)| *pubkey == *account)
            .map(|(_, shared_account)| shared_account)
        {
            if data.lamports() == 0 {
                None
            } else {
                owners.iter().position(|entry| data.owner() == entry)
            }
        } else {
            None
        }
    }

    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        let account_shared_data: Vec<(Pubkey, AccountSharedData)> = self
            .accounts
            .iter()
            .map(|(pubkey, account)| (*pubkey, AccountSharedData::from(account.clone())))
            .collect();
        account_shared_data
            .iter()
            .find(|(_pubkey, _)| *_pubkey == *pubkey)
            .map(|(_, shared_account)| shared_account)
            .cloned()
    }
}

impl TryFrom<proto::InstrContext> for InstrContext {
    type Error = Error;

    fn try_from(input: proto::InstrContext) -> Result<Self, Self::Error> {
        let program_id = Pubkey::new_from_array(
            input
                .program_id
                .try_into()
                .map_err(|_| Error::InvalidPubkeyBytes)?,
        );

        let feature_set: FeatureSet = input
            .epoch_context
            .as_ref()
            .and_then(|epoch_ctx| epoch_ctx.features.as_ref())
            .map(|fs| fs.into())
            .unwrap_or_default();

        let accounts: Vec<(Pubkey, Account)> = input
            .accounts
            .into_iter()
            .map(|acct_state| acct_state.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let instruction_accounts = input
            .instr_accounts
            .into_iter()
            .map(|acct| {
                if acct.index as usize >= accounts.len() {
                    return Err(Error::AccountMissing);
                }
                Ok(AccountMeta {
                    pubkey: accounts[acct.index as usize].0,
                    is_signer: acct.is_signer,
                    is_writable: acct.is_writable,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let instruction = StableInstruction {
            accounts: instruction_accounts.into(),
            data: input.data.into(),
            program_id,
        };

        Ok(Self {
            feature_set,
            accounts,
            instruction,
            cu_avail: input.cu_avail,
            rent_collector: RentCollector::default(),
            last_blockhash: Hash::default(),
            lamports_per_signature: 0,
        })
    }
}

pub fn get_instr_accounts(
    txn_accounts: &[TransactionAccount],
    acct_metas: &StableVec<AccountMeta>,
) -> Vec<InstructionAccount> {
    let mut instruction_accounts: Vec<InstructionAccount> = Vec::with_capacity(acct_metas.len());
    for (instruction_account_index, account_meta) in acct_metas.iter().enumerate() {
        let index_in_transaction = txn_accounts
            .iter()
            .position(|(key, _account)| *key == account_meta.pubkey)
            .unwrap_or(txn_accounts.len()) as IndexOfAccount;
        let index_in_callee = instruction_accounts
            .get(0..instruction_account_index)
            .unwrap()
            .iter()
            .position(|instruction_account| {
                instruction_account.index_in_transaction == index_in_transaction
            })
            .unwrap_or(instruction_account_index) as IndexOfAccount;
        instruction_accounts.push(InstructionAccount {
            index_in_transaction,
            index_in_caller: index_in_transaction,
            index_in_callee,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        });
    }
    instruction_accounts
}

pub struct InstrEffects {
    pub result: Option<InstructionError>,
    pub custom_err: Option<u32>,
    pub modified_accounts: Vec<(Pubkey, Account)>,
    pub cu_avail: u64,
    pub return_data: Vec<u8>,
}

impl From<InstrEffects> for proto::InstrEffects {
    fn from(val: InstrEffects) -> Self {
        proto::InstrEffects {
            result: val
                .result
                .as_ref()
                .map(instr_err_to_num)
                .unwrap_or_default(),
            custom_err: val.custom_err.unwrap_or_default(),
            modified_accounts: val
                .modified_accounts
                .into_iter()
                .map(|(pubkey, account)| proto::AcctState {
                    address: pubkey.to_bytes().to_vec(),
                    owner: account.owner.to_bytes().to_vec(),
                    lamports: account.lamports,
                    data: account.data.to_vec(),
                    executable: account.executable,
                    rent_epoch: account.rent_epoch,
                    seed_addr: None,
                })
                .collect(),
            cu_avail: val.cu_avail,
            return_data: val.return_data,
        }
    }
}

pub fn execute_instr_proto(input: proto::InstrContext) -> Option<proto::InstrEffects> {
    let instr_context = match InstrContext::try_from(input) {
        Ok(context) => context,
        Err(_) => return None,
    };
    let instr_effects = execute_instr(instr_context);
    instr_effects.map(Into::into)
}

fn load_builtins(cache: &mut ProgramCacheForTxBatch, feature_set: &FeatureSet) {
    cache.replenish(
        solana_sdk::bpf_loader_deprecated::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::bpf_loader::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::bpf_loader_upgradeable::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    if feature_set.is_active(&enable_program_runtime_v2_and_loader_v4::id()) {
        cache.replenish(
            solana_sdk::loader_v4::id(),
            Arc::new(ProgramCacheEntry::new_builtin(
                0u64,
                0usize,
                solana_loader_v4_program::Entrypoint::vm,
            )),
        );
    }
    cache.replenish(
        solana_sdk::compute_budget::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_compute_budget_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_stake_program::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_stake_program::stake_instruction::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_system_program::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_system_program::system_processor::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_vote_program::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_vote_program::vote_processor::Entrypoint::vm,
        )),
    );
    if feature_set.is_active(&zk_elgamal_proof_program_enabled::id()) {
        cache.replenish(
            solana_zk_sdk::zk_elgamal_proof_program::id(),
            Arc::new(ProgramCacheEntry::new_builtin(
                0u64,
                0usize,
                solana_zk_elgamal_proof_program::Entrypoint::vm,
            )),
        );
    }

    // If the `CORE_BPF_PROGRAM_ID` and `CORE_BPF_TARGET` environment variables
    // are set, this macro will do the following:
    // * Replace the designated builtin program in the cache with a loaded ELF.
    // * Remove that builtin's program ID from the `builtins` set above.
    load_core_bpf_program!();
}

fn execute_instr(mut input: InstrContext) -> Option<InstrEffects> {
    #[cfg(feature = "core-bpf-conformance")]
    // The BPF version of some builtin programs are built with the assumption
    // that certain features will be active at the time of their deployment.
    // Some of these features are already active on all clusters.
    //
    // As a result, they must be activated when testing for conformance.
    {
        if &input.instruction.program_id == &solana_sdk::address_lookup_table::program::id() {
            // The BPF version of Address Lookup Table depends on `SolGetSysvar`
            // to read slot hash data.
            input
                .feature_set
                .activate(&get_sysvar_syscall_enabled::id(), 0);
        }
    }

    #[cfg(feature = "core-bpf-conformance")]
    // If the fixture declares `cu_avail` to be less than the builtin version's
    // `DEFAULT_COMPUTE_UNITS`, the program should fail on compute meter
    // exhaustion.
    //
    // If the builtin version would otherwise _not_ exhuast the CU meter, give
    // the BPF version the default budget for BPF programs (200k), to avoid any
    // mismatches from the BPF program exhuasting the meter when the builtin
    // did not.
    let compute_budget = {
        let mut budget = ComputeBudget::default();
        if input.cu_avail <= CORE_BPF_DEFAULT_COMPUTE_UNITS {
            budget.compute_unit_limit = 0; // Ensures CU meter exhaustion.
        }
        budget
    };
    #[cfg(not(feature = "core-bpf-conformance"))]
    let compute_budget = ComputeBudget {
        compute_unit_limit: input.cu_avail,
        ..ComputeBudget::default()
    };

    let mut sysvar_cache = SysvarCache::default();

    // First try populating sysvars from accounts list
    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if let Some(account) = input.accounts.iter().find(|(key, _)| key == pubkey) {
            if account.1.lamports > 0 {
                #[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
                // BPF versions of programs, such as Address Lookup Table, rely
                // on the new `SolGetSysvar` syscall. However, APIs for
                // querying slot hashes built on top of `SolGetSysvar` are
                // designed with the assumption that the `SlotHashes` data
                // stored in the sysvar cache is `SlotHashes::size_of()` in
                // length.
                // See https://github.com/anza-xyz/agave/blob/96249691b4b7c873220b27376f271ead38392541/sdk/program/src/sysvar/slot_hashes.rs#L101.
                //
                // Fixtures may provide an incorrect sized slot hashes account,
                // so this step is to rectify it by extending the buffer with
                // all zeroes before adding it to the sysvar cache.
                if &input.instruction.program_id == &solana_sdk::address_lookup_table::program::id()
                    && pubkey == &SlotHashes::id()
                {
                    let data_len = account.1.data.len();
                    if (data_len > 8 && (data_len - 8) % std::mem::size_of::<SlotHash>() == 0)
                        || data_len == 8
                    {
                        if data_len < SlotHashes::size_of() {
                            // Extend the data to the right size.
                            let mut data = vec![0; SlotHashes::size_of()];
                            data[..data_len].copy_from_slice(&account.1.data);
                            return callbackback(&data);
                        }
                    }
                }
                callbackback(&account.1.data);
            }
        }
    });

    // Any default values for missing sysvar values should be set here
    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if *pubkey == Clock::id() {
            // Set the default clock slot to something arbitrary beyond 0
            // This prevents DelayedVisibility errors when executing BPF programs
            let default_clock = Clock {
                slot: 10,
                ..Default::default()
            };
            let clock_data = bincode::serialize(&default_clock).unwrap();
            callbackback(&clock_data);
        }
        if *pubkey == EpochSchedule::id() {
            callbackback(&bincode::serialize(&EpochSchedule::default()).unwrap());
        }
        if *pubkey == Rent::id() {
            callbackback(&bincode::serialize(&Rent::default()).unwrap());
        }
        if *pubkey == last_restart_slot::id() {
            let slot_val = 5000_u64;
            callbackback(&bincode::serialize(&slot_val).unwrap());
        }
    });

    let clock = sysvar_cache.get_clock().unwrap();
    let epoch_schedule = sysvar_cache.get_epoch_schedule().unwrap();

    // Add checks for rent boundaries
    let rent_ = sysvar_cache.get_rent().unwrap();
    let rent = (*rent_).clone();
    if rent.lamports_per_byte_year > u32::MAX.into()
        || rent.exemption_threshold > 999.0
        || rent.exemption_threshold < 0.0
        || rent.burn_percent > 100
    {
        return None;
    };

    let mut transaction_accounts =
        Vec::<TransactionAccount>::with_capacity(input.accounts.len() + 1);
    #[allow(deprecated)]
    input
        .accounts
        .iter()
        .map(|(pubkey, account)| {
            #[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
            // Fixtures provide the program account as a builtin (owned by
            // native loader), but the program-runtime will expect the account
            // owner to match the cache entry.
            //
            // Since we loaded the provided ELF into the cache under loader v3,
            // stub out the program account here.
            //
            // Note: Agave does this during transaction account loading.
            // https://github.com/anza-xyz/agave/blob/6d74d13749829d463fabccebd8203edf0cf4c500/svm/src/account_loader.rs#L246-L249
            if *pubkey == input.instruction.program_id {
                let mut stubbed_out_program_account: AccountSharedData = account.clone().into();
                stubbed_out_program_account.set_owner(solana_sdk::bpf_loader_upgradeable::id());
                stubbed_out_program_account.set_executable(true);
                return (*pubkey, stubbed_out_program_account);
            }
            (*pubkey, AccountSharedData::from(account.clone()))
        })
        .for_each(|x| transaction_accounts.push(x));

    let program_idx = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == input.instruction.program_id)?;

    let mut transaction_context = TransactionContext::new(
        transaction_accounts.clone(),
        rent,
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
    );

    // sigh ... What is this mess?
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    program_cache_for_tx_batch.set_slot_for_tests(clock.slot);

    let program_runtime_environment_v1 =
        solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1(
            &input.feature_set,
            &compute_budget,
            false, /* deployment */
            false, /* debugging_features */
        )
        .unwrap();
    let environments = ProgramRuntimeEnvironments {
        program_runtime_v1: Arc::new(program_runtime_environment_v1),
        ..ProgramRuntimeEnvironments::default()
    };
    program_cache_for_tx_batch.environments = environments.clone();
    program_cache_for_tx_batch.upcoming_environments = Some(environments.clone());

    load_builtins(&mut program_cache_for_tx_batch, &input.feature_set);

    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = sysvar_cache
        .get_recent_blockhashes()
        .ok()
        .and_then(|x| (*x).last().cloned())
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    input.last_blockhash = blockhash;
    input.lamports_per_signature = lamports_per_signature;
    input.rent_collector.epoch = clock.epoch;
    input.rent_collector.epoch_schedule = (*epoch_schedule).clone();
    input.rent_collector.rent = (*rent_).clone();

    let mut newly_loaded_programs = HashSet::<Pubkey>::new();

    for acc in &input.accounts {
        #[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
        // The Core BPF program's ELF has already been added to the cache.
        // Its transaction account was stubbed out, so it can't be loaded via
        // callback (inputs), since the account doesn't contain the ELF.
        // Skip it here.
        if acc.0 == input.instruction.program_id {
            continue;
        }

        // FD rejects duplicate account loads
        if !newly_loaded_programs.insert(acc.0) {
            return None;
        }

        if acc.1.executable && program_cache_for_tx_batch.find(&acc.0).is_none() {
            // load_program_with_pubkey expects the owner to be one of the bpf loader
            if !solana_sdk::loader_v4::check_id(&acc.1.owner)
                && !solana_sdk::bpf_loader_deprecated::check_id(&acc.1.owner)
                && !solana_sdk::bpf_loader::check_id(&acc.1.owner)
                && !solana_sdk::bpf_loader_upgradeable::check_id(&acc.1.owner)
            {
                continue;
            }
            // https://github.com/anza-xyz/agave/blob/af6930da3a99fd0409d3accd9bbe449d82725bd6/svm/src/program_loader.rs#L124
            /* pub fn load_program_with_pubkey<CB: TransactionProcessingCallback, FG: ForkGraph>(
                callbacks: &CB,
                program_cache: &ProgramCache<FG>,
                pubkey: &Pubkey,
                slot: Slot,
                effective_epoch: Epoch,
                epoch_schedule: &EpochSchedule,
                reload: bool,
            ) -> Option<Arc<ProgramCacheEntry>> { */
            if let Some(loaded_program) = program_loader::load_program_with_pubkey(
                &input,
                &environments,
                &acc.0,
                clock.slot,
                false,
            ) {
                program_cache_for_tx_batch.replenish(acc.0, loaded_program);
            }
        }
    }

    let log_collector = LogCollector::new_ref();
    let env_config = EnvironmentConfig::new(
        blockhash,
        None,
        None,
        Arc::new(input.feature_set.clone()),
        lamports_per_signature,
        &sysvar_cache,
    );
    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        env_config,
        Some(log_collector.clone()),
        compute_budget,
    );

    let program_indices = &[program_idx as u16];

    let mut compute_units_consumed = 0u64;

    let mut timings = ExecuteTimings::default();

    let instruction_accounts =
        get_instr_accounts(&transaction_accounts, &input.instruction.accounts);

    // Precompiles (ed25519, secp256k1)
    // Precompiles are programs that run without the VM and without loading any account.
    // They allow to verify signatures, either ed25519 or Ethereum-like secp256k1
    // (note that precompiles can access data from other instructions as well, within
    // the same transaction).
    //
    // They're not run as part of transaction execution, but instead they're run during
    // transaction verification:
    // https://github.com/anza-xyz/agave/blob/34b76ac/runtime/src/bank.rs#L5779
    //
    // During transaction execution, they're skipped (just accounted for CU)
    // https://github.com/anza-xyz/agave/blob/34b76ac/svm/src/message_processor.rs#L93-L108
    //
    // Here we're testing a single instruction.
    // Therefore, when the program is a precompile, we need to run the precompile
    // instead of the regular process_instruction().
    // https://github.com/anza-xyz/agave/blob/34b76ac/sdk/src/precompiles.rs#L107
    //
    // Note: while this test covers the functionality of the precompile, it doesn't
    // cover the fact that the precompile can access data from other instructions.
    // This will be covered in separated tests.
    let program_id = &input.instruction.program_id;
    let is_precompile = is_precompile(program_id, |id| {
        invoke_context.environment_config.feature_set.is_active(id)
    });
    if is_precompile {
        let compiled_instruction = CompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: input.instruction.data.to_vec(),
        };
        let result = verify_if_precompile(
            program_id,
            &compiled_instruction,
            &[compiled_instruction.clone()],
            &invoke_context.environment_config.feature_set,
        );
        return Some(InstrEffects {
            custom_err: None,
            result: if result.is_err() {
                // Precompiles return PrecompileError instead of InstructionError, and
                // there's no from/into conversion to InstructionError nor to u32.
                // For simplicity, we remap first-first, second-second, etc.
                Some(InstructionError::GenericError)
            } else {
                None
            },
            modified_accounts: vec![],
            cu_avail: input.cu_avail,
            return_data: vec![],
        });
    }

    let result = invoke_context.process_instruction(
        &input.instruction.data,
        &instruction_accounts,
        program_indices,
        &mut compute_units_consumed,
        &mut timings,
    );

    #[cfg(feature = "core-bpf-conformance")]
    // To keep alignment with a builtin run, deduct only the CUs the builtin
    // version would have consumed, so the fixture realizes the same CU
    // deduction across both BPF and builtin in its effects.
    let cu_avail = input
        .cu_avail
        .saturating_sub(CORE_BPF_DEFAULT_COMPUTE_UNITS);
    #[cfg(not(feature = "core-bpf-conformance"))]
    let cu_avail = input.cu_avail - compute_units_consumed;

    let return_data = transaction_context.get_return_data().1.to_vec();

    Some(InstrEffects {
        custom_err: if let Err(InstructionError::Custom(code)) = result {
            #[cfg(feature = "core-bpf-conformance")]
            // See comment below under `result` for special-casing of custom
            // errors for Core BPF programs.
            if program_id == &solana_sdk::address_lookup_table::program::id() && code == 10 {
                None
            } else if program_id == &solana_sdk::config::program::id() && code == 0 {
                None
            } else {
                Some(code)
            }
            #[cfg(not(feature = "core-bpf-conformance"))]
            Some(code)
        } else {
            None
        },
        #[allow(clippy::map_identity)]
        result: result.err().map(|err| {
            #[cfg(feature = "core-bpf-conformance")]
            // Some errors don't directly map between builtins and their BPF
            // versions.
            //
            // For example, when a builtin program exceeds the compute budget,
            // the builtin's `DEFAULT_COMPUTE_UNITS` are deducted from the
            // meter, and if the meter is exhuasted, the invoke context will
            // throw `InstructionError::ComputationalBudgetExceeded`.
            // https://github.com/anza-xyz/agave/blob/6d74d13749829d463fabccebd8203edf0cf4c500/program-runtime/src/invoke_context.rs#L73
            // https://github.com/anza-xyz/agave/blob/6d74d13749829d463fabccebd8203edf0cf4c500/program-runtime/src/invoke_context.rs#L574
            //
            // However, for a BPF program, if the compute meter is exhausted,
            // the error comes from the VM, and is converted to
            // `InstructionError::ProgramFailedToComplete`.
            // https://github.com/solana-labs/rbpf/blob/69a52ec6a341bb7374d387173b5e6dc56218fe0c/src/error.rs#L44
            // https://github.com/anza-xyz/agave/blob/6d74d13749829d463fabccebd8203edf0cf4c500/program-runtime/src/invoke_context.rs#L547
            //
            // Therefore, some errors require reconciliation when testing a BPF
            // program against its builtin implementation.
            if err == InstructionError::ProgramFailedToComplete
                && (input.cu_avail <= CORE_BPF_DEFAULT_COMPUTE_UNITS
                    || compute_units_consumed >= input.cu_avail)
            {
                return InstructionError::ComputationalBudgetExceeded;
            }
            #[cfg(feature = "core-bpf-conformance")]
            // Another such error case arises when a program performs a write
            // to an account, but the data it writes is the exact same data
            // that's currently stored in the account state.
            //
            // For builtins, the `TransactionContext` is invoked when any write
            // is performed, asking it whether or not a write is allowed,
            // regardless of the data being written. If the account is not
            // writable, it throws `InstructionError::ReadonlyDataModified`.
            //
            // For BPF programs, writes to readonly accounts are caught _after_
            // the VM finishes execution, when the loader inspects the
            // serialized input data region. If a write was performed that did
            // not modify serialized account state, then no error is thrown.
            //
            // As a result, Core BPF programs have been outfitted with custom
            // errors when `is_writable` checks fail. These errors are
            // special-cased below to avoid fixture mismatches.
            match err {
                InstructionError::Custom(code) => {
                    if program_id == &solana_sdk::address_lookup_table::program::id() {
                        // Special-cased custom error codes for the ALT program.
                        if code == 10 {
                            return InstructionError::ReadonlyDataModified;
                        }
                    }
                    if program_id == &solana_sdk::config::program::id() {
                        // Special-cased custom error codes for the Config program.
                        if code == 0 {
                            return InstructionError::ReadonlyDataModified;
                        }
                    }
                }
                _ => {}
            }
            err
        }),
        modified_accounts: transaction_context
            .deconstruct_without_keys()
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, data)| {
                #[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
                // Fixtures provide the program account as a builtin account
                // (owned by native loader).
                //
                // When we built out the transaction accounts, we stubbed out
                // the program account to be owned by loader v3.
                //
                // We need to swap back in the original here to avoid a
                // mismatch.
                if index == program_idx {
                    if let Some(program_account) = input
                        .accounts
                        .iter()
                        .find(|(pubkey, _)| *pubkey == input.instruction.program_id)
                    {
                        return (program_account.0, program_account.1.clone());
                    }
                }
                (transaction_accounts[index].0, data.into())
            })
            .collect(),
        cu_avail,
        return_data,
    })
}

impl TryFrom<proto::AcctState> for (Pubkey, Account) {
    type Error = Error;

    fn try_from(input: proto::AcctState) -> Result<Self, Self::Error> {
        let pubkey = Pubkey::new_from_array(
            input
                .address
                .try_into()
                .map_err(|_| Error::InvalidPubkeyBytes)?,
        );
        let owner = Pubkey::new_from_array(
            input
                .owner
                .try_into()
                .map_err(|_| Error::InvalidPubkeyBytes)?,
        );

        Ok((
            pubkey,
            Account {
                lamports: input.lamports,
                data: input.data,
                owner,
                executable: input.executable,
                rent_epoch: input.rent_epoch,
            },
        ))
    }
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_init(_log_level: i32) {
    env::set_var("SOLANA_RAYON_THREADS", "1");
    env::set_var("RAYON_NUM_THREADS", "1");
}

#[repr(C)]
pub struct SolCompatFeatures {
    pub struct_size: u64,
    pub hardcoded_features: *const u64,
    pub hardcoded_features_len: u64,
    pub supported_features: *const u64,
    pub supported_features_len: u64,
}

#[repr(C)]
pub struct SolCompatMetadata {
    pub validator_type: u16,
}

unsafe impl Send for SolCompatFeatures {}
unsafe impl Sync for SolCompatFeatures {}

static FEATURES: SolCompatFeatures = SolCompatFeatures {
    struct_size: std::mem::size_of::<SolCompatFeatures>() as u64,
    hardcoded_features: HARDCODED_FEATURES.as_ptr(),
    hardcoded_features_len: HARDCODED_FEATURES.len() as u64,
    supported_features: SUPPORTED_FEATURES.as_ptr(),
    supported_features_len: SUPPORTED_FEATURES.len() as u64,
};

static METADATA: SolCompatMetadata = SolCompatMetadata {
    validator_type: 2, // solfuzz-agave
};

#[no_mangle]
pub unsafe extern "C" fn sol_compat_get_features_v1() -> *const SolCompatFeatures {
    &FEATURES
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_get_metadata_v1() -> *const SolCompatMetadata {
    &METADATA
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_fini() {}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_instr_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let instr_context = match proto::InstrContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let instr_effects = match execute_instr_proto(instr_context) {
        Some(v) => v,
        None => return 0,
    };
    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = instr_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_program_exec() {
        let native_loader_id = solana_sdk::native_loader::id().to_bytes().to_vec();

        // Ensure that a basic account transfer works
        let input = proto::InstrContext {
            program_id: vec![0u8; 32],
            accounts: vec![
                proto::AcctState {
                    address: vec![1u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 1000,
                    data: vec![],
                    executable: false,
                    rent_epoch: 0,
                    seed_addr: None,
                },
                proto::AcctState {
                    address: vec![2u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 0,
                    data: vec![],
                    executable: false,
                    rent_epoch: 0,
                    seed_addr: None,
                },
                proto::AcctState {
                    address: vec![0u8; 32],
                    owner: native_loader_id.clone(),
                    lamports: 10000000,
                    data: b"Solana Program".to_vec(),
                    executable: true,
                    rent_epoch: 0,
                    seed_addr: None,
                },
            ],
            instr_accounts: vec![
                proto::InstrAcct {
                    index: 0,
                    is_signer: true,
                    is_writable: true,
                },
                proto::InstrAcct {
                    index: 1,
                    is_signer: false,
                    is_writable: true,
                },
            ],
            data: vec![
                // Transfer
                0x02, 0x00, 0x00, 0x00, // Lamports
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            cu_avail: 10000u64,
            epoch_context: None,
            slot_context: None,
        };
        let output = execute_instr_proto(input);
        assert_eq!(
            output,
            Some(proto::InstrEffects {
                result: 0,
                custom_err: 0,
                modified_accounts: vec![
                    proto::AcctState {
                        address: vec![1u8; 32],
                        owner: vec![0u8; 32],
                        lamports: 999,
                        data: vec![],
                        executable: false,
                        rent_epoch: 0,
                        seed_addr: None,
                    },
                    proto::AcctState {
                        address: vec![2u8; 32],
                        owner: vec![0u8; 32],
                        lamports: 1,
                        data: vec![],
                        executable: false,
                        rent_epoch: 0,
                        seed_addr: None,
                    },
                    proto::AcctState {
                        address: vec![0u8; 32],
                        owner: native_loader_id.clone(),
                        lamports: 10000000,
                        data: b"Solana Program".to_vec(),
                        executable: true,
                        rent_epoch: 0,
                        seed_addr: None,
                    },
                ],
                cu_avail: 9850u64,
                return_data: vec![],
            })
        );
    }
}
