#![allow(clippy::missing_safety_doc)]

use agave_feature_set::*;
use agave_precompiles::get_precompile;
use agave_precompiles::is_precompile;
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
use solana_sdk_ids::{
    bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, compute_budget, loader_v4,
};
use solana_stable_layout::stable_instruction::StableInstruction;
use solana_stable_layout::stable_vec::StableVec;
use solana_svm::program_loader;
use solana_svm_callback::InvokeContextCallback;
use solana_svm_log_collector::LogCollector;
use solana_svm_timings::ExecuteTimings;
use solana_transaction_context::{
    IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
};

use crate::instr_generated;
use crate::utils::err_map_flatbuffers::instr_err_to_num;
use crate::utils::program::common_flatbuffers::build_output_account;
use solana_svm::transaction_processing_callback::TransactionProcessingCallback;
use solfuzz_agave_macro::{
    declare_core_bpf_default_compute_units, load_bpf_program, load_core_bpf_program,
};
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(any(
    feature = "bpf-program-conformance",
    feature = "core-bpf",
    feature = "core-bpf-conformance",
))]
use solana_account::WritableAccount;
#[cfg(any(feature = "core-bpf", feature = "core-bpf-conformance"))]
use solana_slot_hashes::{SlotHash, SlotHashes};

// If the `CORE_BPF_PROGRAM_ID` variable is set, declares the default compute
// units used by the program's builtin version.
//
// This constant is used to stub-out compute unit conformance checks, since the
// BPF version will use different amounts of CUs.
declare_core_bpf_default_compute_units!();

pub struct InstrContext {
    pub feature_set: FeatureSet,
    pub accounts: Vec<(Pubkey, Account)>,
    pub instruction: StableInstruction,
    pub cu_avail: u64,
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

impl TransactionProcessingCallback for InstrContext {
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, u64)> {
        self.accounts
            .iter()
            .find(|(found_pubkey, _)| *found_pubkey == *pubkey)
            .map(|(_, account)| (AccountSharedData::from(account.clone()), 0u64))
    }
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

pub fn create_invoke_context_fields(
    input: &mut InstrContext,
) -> (
    TransactionContext,
    SysvarCache,
    ProgramCacheForTxBatch,
    Hash,
    u64,
    ComputeBudget,
) {
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
        let mut budget = ComputeBudget::new_with_defaults(false);
        if input.cu_avail <= CORE_BPF_DEFAULT_COMPUTE_UNITS {
            budget.compute_unit_limit = 0; // Ensures CU meter exhaustion.
        }
        budget
    };
    #[cfg(not(feature = "core-bpf-conformance"))]
    let compute_budget = {
        let mut budget = ComputeBudget::new_with_defaults(false);
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

    let mut transaction_accounts = Vec::<TransactionAccount>::with_capacity(input.accounts.len());
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
    program_cache_for_tx_batch.environments = environments.clone();
    program_cache_for_tx_batch.upcoming_environments = Some(environments.clone());

    initialize_program_cache(&mut program_cache_for_tx_batch, &input.feature_set);

    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = (*recent_blockhashes)
        .last()
        .cloned()
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

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
            panic!("Invariant violation: duplicate account load");
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
            if let Some(loaded_program) = program_loader::load_program_with_pubkey(
                input,
                &environments,
                &acc.0,
                clock.slot,
                &mut ExecuteTimings::default(),
                false,
            ) {
                program_cache_for_tx_batch.replenish(acc.0, loaded_program);
            }
        }
    }

    (
        transaction_context,
        sysvar_cache,
        program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
    )
}

pub fn execute_instr(
    context: &instr_generated::InstrContext<'_>,
    builder: &mut flatbuffers::FlatBufferBuilder<'_>,
) {
    let log_collector = LogCollector::new_ref();
    let mut instr_context = InstrContext::from(context);

    let (
        mut transaction_context,
        sysvar_cache,
        mut program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
    ) = create_invoke_context_fields(&mut instr_context);

    let runtime_features = instr_context.feature_set.runtime_features();

    let environment_config = EnvironmentConfig::new(
        blockhash,
        lamports_per_signature,
        &instr_context,
        &runtime_features,
        &sysvar_cache,
    );

    let program_idx = transaction_context
        .find_index_of_account(&instr_context.instruction.program_id)
        .expect("Invariant violation: program account not found in transaction context");

    let mut compute_units_consumed = 0u64;

    let instruction_accounts =
        crate::get_instr_accounts(&transaction_context, &instr_context.instruction.accounts);

    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(log_collector.clone()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::default(),
    );

    invoke_context
        .transaction_context
        .configure_next_instruction_for_tests(
            program_idx,
            instruction_accounts,
            &instr_context.instruction.data,
        )
        .unwrap();

    let result = if invoke_context.is_precompile(&instr_context.instruction.program_id) {
        let instruction_data = instr_context
            .instruction
            .data
            .iter()
            .copied()
            .collect::<Vec<_>>();
        invoke_context.process_precompile(
            &instr_context.instruction.program_id,
            &instr_context.instruction.data,
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
    let cu_avail = input
        .cu_avail
        .saturating_sub(CORE_BPF_DEFAULT_COMPUTE_UNITS);
    #[cfg(not(feature = "core-bpf-conformance"))]
    let cu_avail = instr_context
        .cu_avail
        .saturating_sub(compute_units_consumed);
    let return_data = transaction_context.get_return_data().1.to_vec();

    let account_keys: Vec<Pubkey> = (0..transaction_context.get_number_of_accounts())
        .map(|index| {
            *transaction_context
                .get_key_of_account_at_index(index)
                .clone()
                .unwrap()
        })
        .collect::<Vec<_>>();

    /* Collect modified accounts */
    let accounts_to_save = transaction_context
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
            if let Some((pubkey, program_account)) = input
                .accounts
                .iter()
                .find(|(pubkey, _)| *pubkey == input.instruction.program_id)
            {
                return (&pubkey, &program_account);
            }

            build_output_account(&key, &account, builder)
        })
        .collect::<Vec<_>>();

    let modified_accounts = builder.create_vector_from_iter(accounts_to_save.iter());
    let output_return_data = builder.create_vector(return_data.as_slice());

    let instr_effects = instr_generated::InstrEffects::create(
        builder,
        &instr_generated::InstrEffectsArgs {
            err_code: result
                .clone()
                .err()
                .map(|err| {
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
                        return instr_err_to_num(&InstructionError::ComputationalBudgetExceeded);
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
                            if program_id == &solana_address_lookup_table::program::id() {
                                // Special-cased custom error codes for the ALT program.
                                if code == 10 {
                                    return instr_err_to_num(
                                        &InstructionError::ReadonlyDataModified,
                                    );
                                }
                            }
                            if program_id == &solana_config::program::id() {
                                // Special-cased custom error codes for the Config program.
                                if code == 0 {
                                    return instr_err_to_num(
                                        &InstructionError::ReadonlyDataModified,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    instr_err_to_num(&err)
                })
                .unwrap_or_default(),
            custom_err_code: if let Err(InstructionError::Custom(code)) = result {
                #[cfg(feature = "core-bpf-conformance")]
                // See comment below under `result` for special-casing of custom
                // errors for Core BPF programs.
                if input.instruction.program_id == solana_address_lookup_table::program::id()
                    && code == 10
                {
                    None
                } else if input.instruction.program_id == solana_config::program::id() && code == 0
                {
                    None
                }

                if get_precompile(&instr_context.instruction.program_id, |_| true).is_some() {
                    0
                } else {
                    code
                }
            } else {
                0
            },
            modified_accounts: Some(modified_accounts),
            cu_remaining: cu_avail,
            return_data: Some(output_return_data),
        },
    );
    builder.finish_minimal(instr_effects);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_generated;
    use crate::utils::program::common_flatbuffers::build_output_account;
    use solana_account::WritableAccount;
    use solana_clock::Clock;
    use solana_epoch_schedule::EpochSchedule;
    use solana_rent::Rent;
    use solana_sdk_ids::native_loader;
    use solana_svm::rent_calculator::RENT_EXEMPT_RENT_EPOCH;
    #[allow(deprecated)]
    use solana_sysvar::recent_blockhashes::RecentBlockhashes;
    use solana_sysvar::SysvarSerialize;

    fn create_sysvar_account<'a, T: SysvarSerialize>(
        id: &Pubkey,
        sysvar: T,
        builder: &mut flatbuffers::FlatBufferBuilder<'a>,
    ) -> flatbuffers::WIPOffset<context_generated::Account<'a>> {
        build_output_account(
            id,
            &AccountSharedData::create(
                1,
                bincode::serialize(&sysvar).unwrap(),
                solana_sysvar_id::id(),
                false,
                RENT_EXEMPT_RENT_EPOCH,
            ),
            builder,
        )
    }

    fn make_sysvar_accounts<'a>(
        builder: &mut flatbuffers::FlatBufferBuilder<'a>,
    ) -> Vec<flatbuffers::WIPOffset<context_generated::Account<'a>>> {
        vec![
            create_sysvar_account(&solana_sysvar::clock::id(), Clock::default(), builder),
            create_sysvar_account(&solana_sysvar::rent::id(), Rent::default(), builder),
            create_sysvar_account(
                &solana_sysvar::epoch_schedule::id(),
                EpochSchedule::default(),
                builder,
            ),
            #[allow(deprecated)]
            create_sysvar_account(
                &solana_sysvar::recent_blockhashes::id(),
                RecentBlockhashes::default(),
                builder,
            ),
        ]
    }

    fn with_sysvars<'a>(
        mut v: Vec<flatbuffers::WIPOffset<context_generated::Account<'a>>>,
        builder: &mut flatbuffers::FlatBufferBuilder<'a>,
    ) -> Vec<flatbuffers::WIPOffset<context_generated::Account<'a>>> {
        v.extend(make_sysvar_accounts(builder));
        v
    }

    #[test]
    fn test_system_program_exec() {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1 << 12);
        let native_loader_id = native_loader::id().to_bytes().to_vec();
        let instr_data = builder.create_vector(
            vec![
                // Transfer
                0x02u8, 0x00, 0x00, 0x00, // Lamports
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
            .as_slice(),
        );
        let program_id = context_generated::Pubkey::new(&solana_system_program::id().to_bytes());
        let account_states = with_sysvars(
            vec![
                build_output_account(
                    &Pubkey::new_from_array([1u8; 32]),
                    &AccountSharedData::create(
                        1,
                        vec![],
                        solana_sysvar_id::id(),
                        false,
                        RENT_EXEMPT_RENT_EPOCH,
                    ),
                    &mut builder,
                ),
                build_output_account(
                    &Pubkey::new_from_array([2u8; 32]),
                    &AccountSharedData::create(
                        0,
                        vec![],
                        solana_sysvar_id::id(),
                        false,
                        RENT_EXEMPT_RENT_EPOCH,
                    ),
                    &mut builder,
                ),
                build_output_account(
                    &Pubkey::new_from_array([0u8; 32]),
                    &AccountSharedData::create(
                        10000000,
                        b"Solana Program".to_vec(),
                        native_loader::id(),
                        true,
                        RENT_EXEMPT_RENT_EPOCH,
                    ),
                    &mut builder,
                ),
            ],
            &mut builder,
        );
        let input_account_states = Some(builder.create_vector_from_iter(account_states.iter()));
        let instr_accounts = vec![
            instr_generated::InstrAccount::create(
                &mut builder,
                &instr_generated::InstrAccountArgs {
                    index: 0,
                    is_signer: true,
                    is_writable: true,
                },
            ),
            instr_generated::InstrAccount::create(
                &mut builder,
                &instr_generated::InstrAccountArgs {
                    index: 1,
                    is_signer: false,
                    is_writable: true,
                },
            ),
        ];
        let input_instr_accounts = Some(builder.create_vector_from_iter(instr_accounts.iter()));
        let input = instr_generated::InstrContext::create(
            &mut builder,
            &instr_generated::InstrContextArgs {
                program_id: Some(&program_id),
                account_states: input_account_states,
                instr_accounts: input_instr_accounts,
                cu_avail: 10000u64,
                instr_data: Some(instr_data),
                features: None,
            },
        );
        builder.finish_minimal(input);
        let instr_context_data = builder.finished_data().to_vec();
        let instr_context = unsafe {
            flatbuffers::root_unchecked::<instr_generated::InstrContext<'_>>(
                instr_context_data.as_slice(),
            )
        };

        builder.reset();
        execute_instr(&instr_context, &mut builder);
        let instr_effects_slice = builder.finished_data();
        let instr_effects =
            flatbuffers::root::<instr_generated::InstrEffects<'_>>(instr_effects_slice)
                .expect("Cannot decode instr effects");

        assert_eq!(instr_effects.err_code(), 0);
        assert_eq!(instr_effects.custom_err_code(), 0);
        assert_eq!(instr_effects.cu_remaining(), 9850u64);
        assert!(instr_effects
            .return_data()
            .unwrap()
            .bytes()
            .to_vec()
            .is_empty());

        let modified_accounts = instr_effects.modified_accounts().unwrap();
        assert_eq!(modified_accounts.get(0).address().0.to_vec(), vec![1u8; 32]);
        assert_eq!(modified_accounts.get(0).owner().0.to_vec(), vec![0u8; 32]);
        assert_eq!(modified_accounts.get(0).lamports(), 999);
        assert!(modified_accounts.get(0).data().bytes().to_vec().is_empty());
        assert_eq!(modified_accounts.get(0).executable(), false);

        assert_eq!(modified_accounts.get(1).address().0.to_vec(), vec![2u8; 32]);
        assert_eq!(modified_accounts.get(1).owner().0.to_vec(), vec![0u8; 32]);
        assert_eq!(modified_accounts.get(1).lamports(), 1);
        assert!(modified_accounts.get(1).data().bytes().to_vec().is_empty());
        assert_eq!(modified_accounts.get(1).executable(), false);

        assert_eq!(modified_accounts.get(2).address().0.to_vec(), vec![0u8; 32]);
        assert_eq!(
            modified_accounts.get(2).owner().0.to_vec(),
            native_loader_id.clone()
        );
        assert_eq!(modified_accounts.get(2).lamports(), 10000000);
        assert_eq!(
            modified_accounts.get(2).data().bytes().to_vec(),
            b"Solana Program".to_vec()
        );
        assert_eq!(modified_accounts.get(2).executable(), true);
    }
}
