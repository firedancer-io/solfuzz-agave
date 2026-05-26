#![allow(clippy::missing_safety_doc)]

pub mod block;
pub mod cost;
pub mod elf_loader;
pub mod gossip;
pub mod instr;
pub mod txn;
pub mod utils;
pub mod vm_serialization;
pub mod vm_syscalls;

use agave_feature_set::*;
use std::env;

use crate::utils::feature_u64;

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
    enable_secp256r1_precompile,
    raise_account_cu_limit,
    relax_intrabatch_account_locks,
    increase_cpi_account_info_limit,
];

static SUPPORTED_FEATURES: &[u64] = feature_list![
    blake3_syscall_enabled,
    // zk_token_sdk_enabled, // NOT supported in fd
    stake_raise_minimum_delegation_to_1_sol,
    // stake_minimum_delegation_for_rewards, // reverted in agave
    increase_tx_account_lock_limit,
    disable_turbine_fanout_experiments,
    // enable_big_mod_exp_syscall, // NOT impl in fd
    // deplete_cu_meter_on_vm_failure, // NOT GOOD FOR FUZZING
    // remaining_compute_units_syscall_enabled, // NOT impl in fd
    chained_merkle_conflict_duplicate_proofs,
    deprecate_legacy_vote_ixs,
    // disable_sbpf_v0_execution, // test only (revist for vm v3)
    // reenable_sbpf_v0_execution, // test only (revist for vm v3)
    enable_sbpf_v3_deployment_and_execution,
    enable_get_epoch_stake_syscall,
    verify_retransmitter_signature,
    // vote_only_retransmitter_signed_fec_sets, // reverted in agave
    reenable_zk_elgamal_proof_program,
    // enable_extend_program_checked,  // was un-keyed https://github.com/anza-xyz/agave/pull/11686
    require_static_nonce_account,
    enshrine_slashing_program,
    syscall_parameter_address_restrictions,
    virtual_address_space_adjustments, // depends on syscall_parameter_address_restrictions
    account_data_direct_mapping,       // depends on virtual_address_space_adjustments
    deprecate_rent_exemption_threshold,
    discard_unexpected_data_complete_shreds,
    poseidon_enforce_padding,
    provide_instruction_data_offset_in_vm_r2,
    replace_spl_token_with_p_token,
    raise_block_limits_to_100m, // to be activated in v3.1
    // alpenglow, // TBD
    // raise_cpi_nesting_limit_to_8, // will enable soon after stricter abi constraints feature is active
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
    upgrade_bpf_stake_program_to_v5,
    commission_rate_in_basis_points,
    loader_v3_minimum_extend_program_size,
    direct_account_pointers_in_program_input,
    enable_sha512_syscall,
    disable_sbpf_v0_v1_v2_deployment,
    define_ltds_fee_only_semantics
];

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

unsafe impl Send for SolCompatFeatures {}
unsafe impl Sync for SolCompatFeatures {}

static FEATURES: SolCompatFeatures = SolCompatFeatures {
    struct_size: std::mem::size_of::<SolCompatFeatures>() as u64,
    hardcoded_features: HARDCODED_FEATURES.as_ptr(),
    hardcoded_features_len: HARDCODED_FEATURES.len() as u64,
    supported_features: SUPPORTED_FEATURES.as_ptr(),
    supported_features_len: SUPPORTED_FEATURES.len() as u64,
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_get_features_v1() -> *const SolCompatFeatures {
    &FEATURES
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_fini() {}
