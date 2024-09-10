#![allow(clippy::missing_safety_doc)]

pub mod txn_fuzzer;
pub mod utils;

use std::env;
use solana_sdk::feature_set::*;

use crate::utils::feature_u64;

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
    checked_arithmetic_in_fee_validation,
    reduce_stake_warmup_cooldown,
    require_rent_exempt_split_destination,
    curve25519_restrict_msm_length,
    simplify_alt_bn128_syscall_error_codes,
];

static SUPPORTED_FEATURES: &[u64] = feature_list![
    deprecate_rewards_sysvar,
    pico_inflation,
    warp_timestamp_again,
    blake3_syscall_enabled,
    zk_token_sdk_enabled,
    curve25519_syscall_enabled,
    libsecp256k1_fail_on_bad_count,
    libsecp256k1_fail_on_bad_count2,
    error_on_syscall_bpf_function_hash_collisions,
    reject_callx_r10,
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
    vote_state_add_vote_latency,
    last_restart_slot_sysvar,
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
    validate_fee_collector_account,
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
    deprecate_unused_legacy_vote_plumbing,
    disable_rent_fees_collection,
    chained_merkle_conflict_duplicate_proofs,
];

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/org.solana.sealevel.v1.rs"));
}

#[repr(C)]
pub struct SolCompatFeatures {
    pub struct_size: u64,
    pub hardcoded_features: *const u64,
    pub hardcoded_features_len: u64,
    pub supported_features: *const u64,
    pub supported_features_len: u64,
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

#[no_mangle]
pub unsafe extern "C" fn sol_compat_get_features_v1() -> *const SolCompatFeatures {
    &FEATURES
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_init() {
    env::set_var("SOLANA_RAYON_THREADS", "1");
    env::set_var("RAYON_NUM_THREADS", "1");
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_fini() {}