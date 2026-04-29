#![allow(clippy::missing_safety_doc)]

pub mod block;
pub mod cost;
pub mod elf_loader;
pub mod gossip;
pub mod txn;
pub mod utils;
pub mod vm_syscalls;

use agave_feature_set::*;
use agave_precompiles::get_precompile;
use agave_precompiles::is_precompile;
use prost::Message;
use solana_account::{Account, AccountSharedData};
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_compute_budget::compute_budget::SVMTransactionExecutionCost;
use solana_hash::Hash;
use solana_instruction::error::InstructionError;
use solana_instruction::AccountMeta;
use solana_precompile_error::PrecompileError;
use solana_program_runtime::invoke_context::EnvironmentConfig;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::loaded_programs::ProgramCacheEntry;
use solana_program_runtime::loaded_programs::ProgramCacheForTxBatch;
use solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_pubkey::Pubkey;
use solana_runtime::rent_collector::RentCollector;
use solana_sdk_ids::{
    bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, compute_budget, loader_v4,
};
use solana_stable_layout::stable_instruction::StableInstruction;
use solana_stable_layout::stable_vec::StableVec;
use solana_svm::program_loader;
use solana_svm_callback::InvokeContextCallback;
use solana_svm_log_collector::LogCollector;
use solana_svm_timings::ExecuteTimings;
use solana_transaction_context::MAX_INSTRUCTION_DATA_LEN;
use solana_transaction_context::{
    instruction_accounts::InstructionAccount, transaction::TransactionContext,
    transaction_accounts::KeyedAccountSharedData, IndexOfAccount,
};

use crate::utils::err_map::instr_err_to_num;
use crate::utils::{feature_set_from_protos, feature_u64};
use solana_svm::transaction_processing_callback::TransactionProcessingCallback;
use solfuzz_agave_macro::{
    declare_core_bpf_default_compute_units, load_bpf_program, load_core_bpf_program,
};
use std::collections::HashSet;
use std::env;
use std::ffi::c_int;
use std::sync::Arc;
use thiserror::Error;

#[cfg(any(
    feature = "bpf-program-conformance",
    feature = "core-bpf",
    feature = "core-bpf-conformance",
))]
use solana_account::WritableAccount;
#[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
use solana_slot_hashes::{SlotHash, SlotHashes};

// macro to rewrite &[IDENTIFIER, ...] to &[feature_u64(IDENTIFIER::id()), ...]
#[macro_export]
macro_rules! feature_list {
    ($($feature:ident),*$(,)?) => {
        &[$(feature_u64(&$feature::id())),*]
    };
}

pub use full_inflation::mainnet::certusone::enable as full_inflation_enable;
pub use full_inflation::mainnet::certusone::vote as full_inflation_vote;

pub static HARDCODED_FEATURES: &[u64] = feature_list![
    deprecate_rewards_sysvar,
    pico_inflation,
    full_inflation_vote,
    full_inflation_enable,
    secp256k1_program_enabled,
    spl_token_v2_multisig_fix,
    no_overflow_rent_distribution,
    filter_stake_delegation_accounts,
    require_custodian_for_locked_stake_authorize,
    spl_token_v2_self_transfer_fix,
    warp_timestamp_again,
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
    curve25519_syscall_enabled,
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
    disable_deploy_of_alloc_free_syscall,
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
    enable_bpf_loader_extend_program_ix,
    enable_early_verification_of_account_modifications,
    skip_rent_rewrites,
    prevent_crediting_accounts_that_end_rent_paying,
    cap_bpf_program_instruction_accounts,
    loosen_cpi_size_restriction,
    use_default_units_in_fee_calculation,
    compact_vote_state_updates,
    incremental_snapshot_only_incremental_hash_calculation,
    disable_cpi_setting_executable_and_rent_epoch,
    on_load_preserve_rent_epoch_for_rent_exempt_accounts,
    account_hash_ignore_slot,
    set_exempt_rent_epoch_max,
    relax_authority_signer_check_for_lookup_table_creation,
    stop_sibling_instruction_search_at_parent,
    vote_state_update_root_fix,
    cap_accounts_data_allocations_per_transaction,
    epoch_accounts_hash,
    remove_deprecated_request_unit_ix,
    disable_rehash_for_rent_epoch,
    limit_max_instruction_trace_length,
    check_syscall_outputs_do_not_overlap,
    enable_bpf_loader_set_authority_checked_ix,
    enable_alt_bn128_syscall,
    enable_program_redeployment_cooldown,
    commission_updates_only_allowed_in_first_half_of_epoch,
    enable_turbine_fanout_experiments,
    move_serialized_len_ptr_in_cpi,
    update_hashes_per_tick,
    disable_builtin_loader_ownership_chains,
    cap_transaction_accounts_data_size,
    remove_congestion_multiplier_from_fee_calculation,
    enable_request_heap_frame_ix,
    prevent_rent_paying_rent_recipients,
    delay_visibility_of_program_deployment,
    apply_cost_tracker_during_replay,
    add_set_tx_loaded_accounts_data_size_instruction,
    switch_to_new_elf_parser,
    round_up_heap_size,
    remove_bpf_loader_incorrect_program_id,
    native_programs_consume_cu,
    simplify_writable_program_account_check,
    stop_truncating_strings_in_syscalls,
    clean_up_delegation_errors,
    vote_state_add_vote_latency,
    checked_arithmetic_in_fee_validation,
    last_restart_slot_sysvar,
    reduce_stake_warmup_cooldown,
    revise_turbine_epoch_stakes,
    enable_poseidon_syscall,
    timely_vote_credits,
    require_rent_exempt_split_destination,
    better_error_codes_for_tx_lamport_check,
    enable_alt_bn128_compression_syscall,
    update_hashes_per_tick2,
    update_hashes_per_tick3,
    update_hashes_per_tick4,
    update_hashes_per_tick5,
    update_hashes_per_tick6,
    validate_fee_collector_account,
    drop_legacy_shreds,
    consume_blockstore_duplicate_proofs,
    index_erasure_conflict_duplicate_proofs,
    curve25519_restrict_msm_length,
    allow_commission_decrease_at_any_time,
    merkle_conflict_duplicate_proofs,
    disable_bpf_loader_instructions,
    cost_model_requested_write_lock_cost,
    enable_gossip_duplicate_proof_ingestion,
    enable_chained_merkle_shreds,
    remove_rounding_in_fee_calculation,
    enable_tower_sync_ix,
    deprecate_unused_legacy_vote_plumbing,
    reward_full_priority_fee,
    disable_rent_fees_collection,
    add_new_reserved_account_keys,
    simplify_alt_bn128_syscall_error_codes,
    abort_on_invalid_curve,
    ed25519_precompile_verify_strict,
    zk_elgamal_proof_program_enabled,
    move_stake_and_move_lamports_ixs,
    partitioned_epoch_rewards_superfeature,
    get_sysvar_syscall_enabled,
    migrate_feature_gate_program_to_core_bpf,
    migrate_config_program_to_core_bpf,
    migrate_address_lookup_table_program_to_core_bpf,
    migrate_stake_program_to_core_bpf,
    disable_account_loader_special_case,
    remove_accounts_executable_flag_checks,
    accounts_lt_hash,
    remove_accounts_delta_hash,
    snapshots_lt_hash,
    reserve_minimal_cus_for_builtin_instructions,
    raise_block_limits_to_50m,
    move_precompile_verification_to_svm,
    enable_transaction_loading_failure_fees,
    disable_partitioned_rent_collection,
    formalize_loaded_transaction_data_size,
    // create_slashing_program, // renamed to enshrine_slashing_program
    drop_unchained_merkle_shreds,
    // enable_zk_proof_from_account, // disabled
    // enable_zk_transfer_with_fee, // disabled
    fix_alt_bn128_multiplication_input_length,
    // include_loaded_accounts_data_size_in_fee_calculation, // was reverted
    raise_block_limits_to_60m,
    vote_only_full_fec_sets,
    enable_sbpf_v1_deployment_and_execution,
    enable_sbpf_v2_deployment_and_execution,
    enable_turbine_extended_fanout_experiments,
    mask_out_rent_epoch_in_vm_serialization,
    disable_zk_elgamal_proof_program,
    enable_vote_address_leader_schedule,
    vote_state_v4,
    fix_alt_bn128_pairing_length_check,
    static_instruction_limit,
    switch_to_chacha8_turbine,
    enforce_fixed_fec_set,
];

static SUPPORTED_FEATURES: &[u64] = feature_list![
    blake3_syscall_enabled,
    // zk_token_sdk_enabled, // NOT supported in fd
    stake_raise_minimum_delegation_to_1_sol,
    // stake_minimum_delegation_for_rewards, // reverted in fd (firedancer-io/firedancer#9325)
    increase_tx_account_lock_limit,
    disable_turbine_fanout_experiments,
    // enable_big_mod_exp_syscall, // NOT impl in fd
    // deplete_cu_meter_on_vm_failure, // NOT GOOD FOR FUZZING
    // remaining_compute_units_syscall_enabled, // NOT impl in fd
    chained_merkle_conflict_duplicate_proofs,
    deprecate_legacy_vote_ixs,
    enable_secp256r1_precompile,
    // disable_sbpf_v0_execution, // test only (revist for vm v3)
    // reenable_sbpf_v0_execution, // test only (revist for vm v3)
    enable_sbpf_v3_deployment_and_execution,
    enable_get_epoch_stake_syscall,
    verify_retransmitter_signature,
    vote_only_retransmitter_signed_fec_sets,
    reenable_zk_elgamal_proof_program,
    enable_extend_program_checked,
    require_static_nonce_account,
    enshrine_slashing_program,
    syscall_parameter_address_restrictions,
    virtual_address_space_adjustments, // depends on syscall_parameter_address_restrictions
    account_data_direct_mapping, // depends on virtual_address_space_adjustments
    deprecate_rent_exemption_threshold,
    discard_unexpected_data_complete_shreds,
    increase_cpi_account_info_limit,
    poseidon_enforce_padding,
    provide_instruction_data_offset_in_vm_r2,
    replace_spl_token_with_p_token,
    raise_block_limits_to_100m, // to be activated in v3.1
    // alpenglow, // TBD
    raise_account_cu_limit,
    // raise_cpi_nesting_limit_to_8, // will enable soon after stricter abi constraints feature is active
    relax_intrabatch_account_locks,
    // enable_loader_v4,
    enable_bls12_381_syscall,
    alt_bn128_little_endian,
    enable_alt_bn128_g2_syscalls,
    bls_pubkey_management_in_vote_account,
    relax_programdata_account_check_migration,
    remove_simple_vote_from_cost_model,
    limit_instruction_accounts,
    validator_admission_ticket,
    create_account_allow_prefund,
    delay_commission_updates,
    validate_chained_block_id,
    upgrade_bpf_stake_program_to_v5
];

// If the `CORE_BPF_PROGRAM_ID` variable is set, declares the default compute
// units used by the program's builtin version.
//
// This constant is used to stub-out compute unit conformance checks, since the
// BPF version will use different amounts of CUs.
declare_core_bpf_default_compute_units!();

use protosol::protos;

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

impl InvokeContextCallback for InstrContext {
    fn is_precompile(&self, program_id: &Pubkey) -> bool {
        is_precompile(program_id, |feature_id: &Pubkey| {
            self.feature_set.is_active(feature_id)
        })
    }

    fn process_precompile(
        &self,
        program_id: &Pubkey,
        data: &[u8],
        instruction_datas: Vec<&[u8]>,
    ) -> std::result::Result<(), PrecompileError> {
        if let Some(precompile) = get_precompile(program_id, |feature_id: &Pubkey| {
            self.feature_set.is_active(feature_id)
        }) {
            precompile.verify(data, &instruction_datas, &self.feature_set)
        } else {
            Err(PrecompileError::InvalidPublicKey)
        }
    }
}

// Rust's orphan rules forbid implementing an external trait for an external type
// so we need to separate this out.
pub(crate) struct SnapshotInvokeContext {
    feature_set: FeatureSet,
}

impl SnapshotInvokeContext {
    pub(crate) fn new(feature_set: FeatureSet) -> Self {
        Self { feature_set }
    }
}

/// TODO: use InvokeContextCallback directly within the Agave SVM harness
impl InvokeContextCallback for SnapshotInvokeContext {
    fn is_precompile(&self, program_id: &Pubkey) -> bool {
        is_precompile(program_id, |feature_id: &Pubkey| {
            self.feature_set.is_active(feature_id)
        })
    }

    fn process_precompile(
        &self,
        program_id: &Pubkey,
        data: &[u8],
        instruction_datas: Vec<&[u8]>,
    ) -> std::result::Result<(), PrecompileError> {
        if let Some(precompile) = get_precompile(program_id, |feature_id: &Pubkey| {
            self.feature_set.is_active(feature_id)
        }) {
            precompile.verify(data, &instruction_datas, &self.feature_set)
        } else {
            Err(PrecompileError::InvalidPublicKey)
        }
    }
}

impl TransactionProcessingCallback for InstrContext {
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, u64)> {
        self.accounts
            .iter()
            .find(|(found_pubkey, _)| *found_pubkey == *pubkey)
            .map(|(_, account)| (AccountSharedData::from(account.clone()), 0u64))
    }
}

impl TryFrom<protos::InstrContext> for InstrContext {
    type Error = Error;

    fn try_from(input: protos::InstrContext) -> Result<Self, Self::Error> {
        let program_id = Pubkey::new_from_array(
            input
                .program_id
                .try_into()
                .map_err(|_| Error::InvalidPubkeyBytes)?,
        );

        let feature_set: FeatureSet = input
            .features
            .as_ref()
            .map(feature_set_from_protos)
            .unwrap_or_default();

        let accounts: Vec<(Pubkey, Account)> = input.accounts.into_iter().map(Into::into).collect();

        // Match Firedancer harness limit (FD_INSTR_ACCT_MAX = 1094)
        // which is derived from the MTU
        // (see FD_BPF_INSTR_ACCT_MAX comment in Firedancer)
        const MAX_INSTR_ACCOUNTS: usize = 1094;
        assert!(
            input.instr_accounts.len() <= MAX_INSTR_ACCOUNTS,
            "invariant violation: too many instruction accounts"
        );

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

        if input.data.len() > MAX_INSTRUCTION_DATA_LEN {
            panic!(
                "invariant violation: instr data sz is too large {} > {}",
                input.data.len(),
                MAX_INSTRUCTION_DATA_LEN
            );
        }

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
    txn_context: &TransactionContext,
    acct_metas: &StableVec<AccountMeta>,
) -> Vec<InstructionAccount> {
    let mut instruction_accounts: Vec<InstructionAccount> =
        Vec::with_capacity(acct_metas.len().try_into().unwrap());
    for account_meta in acct_metas.iter() {
        let index_in_transaction = txn_context
            .find_index_of_account(&account_meta.pubkey)
            .expect("invariant violation: account not found in transaction context")
            as IndexOfAccount;
        instruction_accounts.push(InstructionAccount::new(
            index_in_transaction,
            account_meta.is_signer,
            account_meta.is_writable,
        ));
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

impl From<InstrEffects> for protos::InstrEffects {
    fn from(val: InstrEffects) -> Self {
        protos::InstrEffects {
            result: val
                .result
                .as_ref()
                .map(instr_err_to_num)
                .unwrap_or_default(),
            custom_err: val.custom_err.unwrap_or_default(),
            modified_accounts: val
                .modified_accounts
                .into_iter()
                .map(|(pubkey, account)| protos::AcctState {
                    address: pubkey.to_bytes().to_vec(),
                    owner: account.owner.to_bytes().to_vec(),
                    lamports: account.lamports,
                    data: account.data.to_vec(),
                    executable: account.executable,
                })
                .collect(),
            cu_avail: val.cu_avail,
            return_data: val.return_data,
        }
    }
}

pub fn execute_instr_proto(input: protos::InstrContext) -> Option<protos::InstrEffects> {
    let Ok(instr_context) = InstrContext::try_from(input) else {
        return None;
    };
    let instr_effects = execute_instr(instr_context);
    instr_effects.map(Into::into)
}

fn initialize_program_cache(cache: &mut ProgramCacheForTxBatch, feature_set: &FeatureSet) {
    // Load builtin programs into the cache.
    cache.replenish(
        bpf_loader_deprecated::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        bpf_loader::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        bpf_loader_upgradeable::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    if feature_set.is_active(&enable_loader_v4::id()) {
        cache.replenish(
            loader_v4::id(),
            Arc::new(ProgramCacheEntry::new_builtin(
                0u64,
                0usize,
                solana_loader_v4_program::Entrypoint::vm,
            )),
        );
    }
    cache.replenish(
        compute_budget::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0u64,
            0usize,
            solana_compute_budget_program::Entrypoint::vm,
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

    // If the `core-bpf` or `core-bpf-conformance` feature is enabled, and the
    // `CORE_BPF_PROGRAM_ID` and `CORE_BPF_TARGET` environment variables are
    // set, this macro will replace the designated builtin program in the cache
    // with a loaded ELF.
    load_core_bpf_program!();

    // If the `bpf-program-conformance` feature is enabled, and the
    // `BPF_PROGRAM_ID` and `BPF_TARGET` environment variables are set, this
    // macro will load the provided ELF into the cache.
    load_bpf_program!();
}

fn create_invoke_context_fields(
    input: &mut InstrContext,
    populate_program_cache: bool,
) -> Option<(
    TransactionContext<'_>,
    SysvarCache,
    ProgramCacheForTxBatch,
    Hash,
    u64,
    ComputeBudget,
    ProgramRuntimeEnvironments,
)> {
    #[cfg(feature = "core-bpf-conformance")]
    // The BPF version of some builtin programs are built with the assumption
    // that certain features will be active at the time of their deployment.
    // Some of these features are already active on all clusters.
    //
    // As a result, they must be activated when testing for conformance.
    {
        if &input.instruction.program_id == &solana_address_lookup_table::program::id() {
            // The BPF version of Address Lookup Table depends on `SolGetSysvar`
            // to read slot hash data.
            input
                .feature_set
                .activate(&get_sysvar_syscall_enabled::id(), 0);
        }
    }

    // Do not diverge from Agave on post-activation features.
    let simd_0268_active = input
        .feature_set
        .is_active(&raise_cpi_nesting_limit_to_8::id());
    let simd_0339_active = input
        .feature_set
        .is_active(&increase_cpi_account_info_limit::id());

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
        let mut budget = ComputeBudget::new_with_defaults(simd_0268_active, simd_0339_active);
        if input.cu_avail <= CORE_BPF_DEFAULT_COMPUTE_UNITS {
            budget.compute_unit_limit = 0; // Ensures CU meter exhaustion.
        }
        budget
    };
    #[cfg(not(feature = "core-bpf-conformance"))]
    let compute_budget = {
        let mut budget = ComputeBudget::new_with_defaults(simd_0268_active, simd_0339_active);
        budget.compute_unit_limit = input.cu_avail;
        budget
    };

    let mut sysvar_cache = SysvarCache::default();

    // First try populating sysvars from accounts list
    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if let Some(account) = input.accounts.iter().find(|(key, _)| key == pubkey) {
            if account.1.lamports > 0 {
                callbackback(&account.1.data);
            }
        }
    });

    /* Sysvars must exist in the input */
    let clock = sysvar_cache.get_clock().unwrap();
    let epoch_schedule = sysvar_cache.get_epoch_schedule().unwrap();
    let rent = sysvar_cache.get_rent().unwrap();
    #[allow(deprecated)]
    let recent_blockhashes = sysvar_cache.get_recent_blockhashes().unwrap();

    if !input
        .accounts
        .iter()
        .any(|(pubkey, _)| pubkey == &input.instruction.program_id)
    {
        input.accounts.push((
            input.instruction.program_id,
            AccountSharedData::default().into(),
        ));
    }

    let mut transaction_accounts =
        Vec::<KeyedAccountSharedData>::with_capacity(input.accounts.len());
    #[allow(deprecated)]
    input
        .accounts
        .iter()
        .map(|(pubkey, account)| {
            #[cfg(any(
                feature = "bpf-program-conformance",
                feature = "core-bpf",
                feature = "core-bpf-conformance",
            ))]
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
                stubbed_out_program_account.set_owner(bpf_loader_upgradeable::id());
                stubbed_out_program_account.set_executable(true);
                return (*pubkey, stubbed_out_program_account);
            }
            (*pubkey, AccountSharedData::from(account.clone()))
        })
        .for_each(|x| transaction_accounts.push(x));

    let transaction_context = TransactionContext::new(
        transaction_accounts.clone(),
        (*rent).clone(),
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
        1,
    );

    // sigh ... What is this mess?
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    program_cache_for_tx_batch.set_slot_for_tests(clock.slot);

    let program_runtime_environment_v1 = agave_syscalls::create_program_runtime_environment_v1(
        &input.feature_set.runtime_features(),
        &compute_budget.to_budget(),
        false,                                      /* deployment */
        std::env::var("ENABLE_VM_TRACING").is_ok(), /* debugging_features */
    )
    .unwrap();
    let environments = ProgramRuntimeEnvironments {
        program_runtime_v1: Arc::new(program_runtime_environment_v1),
        ..ProgramRuntimeEnvironments::default()
    };

    initialize_program_cache(&mut program_cache_for_tx_batch, &input.feature_set);

    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = (*recent_blockhashes)
        .last()
        .cloned()
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    input.last_blockhash = blockhash;
    input.lamports_per_signature = lamports_per_signature;
    input.rent_collector.epoch = clock.epoch;
    input.rent_collector.epoch_schedule = (*epoch_schedule).clone();
    input.rent_collector.rent = (*rent).clone();

    if populate_program_cache {
        let mut newly_loaded_programs = HashSet::<Pubkey>::new();

        for acc in &input.accounts {
            #[cfg(any(
                feature = "bpf-program-conformance",
                feature = "core-bpf",
                feature = "core-bpf-conformance",
            ))]
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

            if program_cache_for_tx_batch.find(&acc.0).is_none() {
                // load_program_with_pubkey expects the owner to be one of the bpf loader
                if !loader_v4::check_id(&acc.1.owner)
                    && !bpf_loader_deprecated::check_id(&acc.1.owner)
                    && !bpf_loader::check_id(&acc.1.owner)
                    && !bpf_loader_upgradeable::check_id(&acc.1.owner)
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
                if let Some((loaded_program, _)) = program_loader::load_program_with_pubkey(
                    input,
                    &environments,
                    &acc.0,
                    clock.slot,
                    &mut ExecuteTimings::default(),
                ) {
                    program_cache_for_tx_batch.replenish(acc.0, loaded_program);
                }
            }
        }
    }

    Some((
        transaction_context,
        sysvar_cache,
        program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
        environments,
    ))
}

fn execute_instr(mut input: InstrContext) -> Option<InstrEffects> {
    let log_collector = LogCollector::new_ref();

    // Extract all needed values before mutable borrow
    let program_id = input.instruction.program_id;
    let instruction_data = input.instruction.data.to_vec();
    let runtime_features = input.feature_set.runtime_features();
    let feature_set_snapshot = input.feature_set.clone();
    let instruction_accounts_snapshot: StableVec<AccountMeta> = input
        .instruction
        .accounts
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();
    let initial_cu_avail = input.cu_avail;

    let (
        mut transaction_context,
        sysvar_cache,
        mut program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
        environments,
    ) = create_invoke_context_fields(&mut input, true)?;

    // Get accounts immediately after mutable borrow is released, before creating EnvironmentConfig
    let instruction_accounts =
        get_instr_accounts(&transaction_context, &instruction_accounts_snapshot);

    let callback_context = SnapshotInvokeContext::new(feature_set_snapshot);

    // Create EnvironmentConfig (mutable borrow on input is released)
    let environment_config = EnvironmentConfig::new(
        blockhash,
        lamports_per_signature,
        &callback_context,
        &runtime_features,
        &environments,
        &environments,
        &sysvar_cache,
    );

    let program_idx = transaction_context.find_index_of_account(&program_id)?;

    let mut compute_units_consumed = 0u64;

    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(log_collector.clone()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::new_with_defaults(
            runtime_features.increase_cpi_account_info_limit,
        ),
    );

    invoke_context
        .transaction_context
        .configure_top_level_instruction_for_tests(
            program_idx,
            instruction_accounts,
            instruction_data.clone(),
        )
        .unwrap();

    let result = if invoke_context.is_precompile(&program_id) {
        invoke_context.process_precompile(
            &program_id,
            &instruction_data,
            [instruction_data.as_slice()].into_iter(),
        )
    } else {
        invoke_context
            .process_instruction(&mut compute_units_consumed, &mut ExecuteTimings::default())
    };

    #[cfg(feature = "core-bpf-conformance")]
    // To keep alignment with a builtin run, deduct only the CUs the builtin
    // version would have consumed, so the fixture realizes the same CU
    // deduction across both BPF and builtin in its effects.
    let cu_avail = initial_cu_avail.saturating_sub(CORE_BPF_DEFAULT_COMPUTE_UNITS);
    #[cfg(not(feature = "core-bpf-conformance"))]
    let cu_avail = initial_cu_avail.saturating_sub(compute_units_consumed);
    let return_data = transaction_context.get_return_data().1.to_vec();

    let account_keys: Vec<Pubkey> = (0..transaction_context.get_number_of_accounts())
        .map(|index| {
            *transaction_context
                .get_key_of_account_at_index(index)
                .clone()
                .unwrap()
        })
        .collect::<Vec<_>>();

    Some(InstrEffects {
        custom_err: if let Err(InstructionError::Custom(code)) = result {
            #[cfg(feature = "core-bpf-conformance")]
            // See comment below under `result` for special-casing of custom
            // errors for Core BPF programs.
            if program_id == solana_address_lookup_table::program::id() && code == 10 {
                None
            } else if program_id == solana_config::program::id() && code == 0 {
                None
            }

            if get_precompile(&program_id, |_| true).is_some() {
                Some(0)
            } else {
                Some(code)
            }
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
                && (initial_cu_avail <= CORE_BPF_DEFAULT_COMPUTE_UNITS
                    || compute_units_consumed >= initial_cu_avail)
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
                    if program_id == solana_address_lookup_table::program::id() {
                        // Special-cased custom error codes for the ALT program.
                        if code == 10 {
                            return InstructionError::ReadonlyDataModified;
                        }
                    }
                    if program_id == solana_config::program::id() {
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
            .zip(account_keys)
            .map(|(account, key)| {
                #[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
                // Fixtures provide the program account as a builtin account
                // (owned by native loader).
                //
                // When we built out the transaction accounts, we stubbed out
                // the program account to be owned by loader v3.
                //
                // We need to swap back in the original here to avoid a
                // mismatch.
                if let Some(program_account) = accounts_snapshot
                    .iter()
                    .find(|(pubkey, _)| *pubkey == program_id)
                {
                    return (program_account.0, program_account.1.clone());
                }
                (key, account.into())
            })
            .collect(),
        cu_avail,
        return_data,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_init(_log_level: i32) {
    unsafe {
        env::set_var("SOLANA_RAYON_THREADS", "1");
        env::set_var("RAYON_NUM_THREADS", "1");
    }
    if env::var("ENABLE_SOLANA_LOGGER").is_ok() {
        /* Pairs with RUST_LOG={trace,debug,info,etc} */
        agave_logger::setup(); // renamed in Agave v3.1
    }
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_get_features_v1() -> *const SolCompatFeatures {
    &FEATURES
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_get_metadata_v1() -> *const SolCompatMetadata {
    &METADATA
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_fini() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_instr_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(instr_context) = protos::InstrContext::decode(in_slice) else {
        return 0;
    };
    let Some(instr_effects) = execute_instr_proto(instr_context) else {
        return 0;
    };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    let out_vec = instr_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };

    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_clock::Clock;
    use solana_epoch_schedule::EpochSchedule;
    use solana_rent::Rent;
    use solana_sdk_ids::native_loader;
    #[allow(deprecated)]
    use solana_sysvar::recent_blockhashes::RecentBlockhashes;
    use solana_sysvar::SysvarSerialize;

    fn create_sysvar_account<T: SysvarSerialize>(id: &Pubkey, sysvar: T) -> protos::AcctState {
        protos::AcctState {
            address: id.to_bytes().to_vec(),
            owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
            lamports: 1,
            data: bincode::serialize(&sysvar).unwrap(),
            executable: false,
        }
    }

    fn make_sysvar_accounts() -> Vec<protos::AcctState> {
        vec![
            create_sysvar_account(&solana_sysvar::clock::id(), Clock::default()),
            create_sysvar_account(&solana_sysvar::rent::id(), Rent::default()),
            create_sysvar_account(
                &solana_sysvar::epoch_schedule::id(),
                EpochSchedule::default(),
            ),
            #[allow(deprecated)]
            create_sysvar_account(
                &solana_sysvar::recent_blockhashes::id(),
                RecentBlockhashes::default(),
            ),
        ]
    }

    fn with_sysvars(mut v: Vec<protos::AcctState>) -> Vec<protos::AcctState> {
        v.extend(make_sysvar_accounts());
        v
    }

    #[test]
    fn test_system_program_exec() {
        let native_loader_id = native_loader::id().to_bytes().to_vec();

        // Ensure that a basic account transfer works
        let input = protos::InstrContext {
            program_id: vec![0u8; 32],
            accounts: with_sysvars(vec![
                protos::AcctState {
                    address: vec![1u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 1000,
                    data: vec![],
                    executable: false,
                },
                protos::AcctState {
                    address: vec![2u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 0,
                    data: vec![],
                    executable: false,
                },
                protos::AcctState {
                    address: vec![0u8; 32],
                    owner: native_loader_id.clone(),
                    lamports: 10000000,
                    data: b"Solana Program".to_vec(),
                    executable: true,
                },
            ]),
            instr_accounts: vec![
                protos::InstrAcct {
                    index: 0,
                    is_signer: true,
                    is_writable: true,
                },
                protos::InstrAcct {
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
            features: None,
        };
        let output = execute_instr_proto(input);
        assert_eq!(
            output,
            Some(protos::InstrEffects {
                result: 0,
                custom_err: 0,
                modified_accounts: with_sysvars(vec![
                    protos::AcctState {
                        address: vec![1u8; 32],
                        owner: vec![0u8; 32],
                        lamports: 999,
                        data: vec![],
                        executable: false,
                    },
                    protos::AcctState {
                        address: vec![2u8; 32],
                        owner: vec![0u8; 32],
                        lamports: 1,
                        data: vec![],
                        executable: false,
                    },
                    protos::AcctState {
                        address: vec![0u8; 32],
                        owner: native_loader_id.clone(),
                        lamports: 10000000,
                        data: b"Solana Program".to_vec(),
                        executable: true,
                    },
                ]),
                cu_avail: 9850u64,
                return_data: vec![],
            })
        );
    }
}
