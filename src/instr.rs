use std::ffi::c_int;

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
use solana_svm::transaction_processing_callback::TransactionProcessingCallback;
use solana_svm_callback::InvokeContextCallback;
use solana_svm_log_collector::LogCollector;
use solana_svm_timings::ExecuteTimings;
use solana_transaction_context::MAX_INSTRUCTION_DATA_LEN;
use solana_transaction_context::{
    InstructionAccount, TransactionContext,
    transaction_accounts::KeyedAccountSharedData, IndexOfAccount,
};

use crate::utils::err_map::instr_err_to_num;
use crate::utils::feature_set_from_protos;
use protosol::protos;
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

declare_core_bpf_default_compute_units!();

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
    let Some(instr_effects) = execute_instr(instr_context) else {
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

impl From<protos::InstrContext> for InstrContext {
    fn from(input: protos::InstrContext) -> Self {
        let program_id = Pubkey::new_from_array(
            input
                .program_id
                .try_into()
                .expect("invariant violation: invalid program_id pubkey bytes"),
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

        let instruction_accounts: Vec<AccountMeta> = input
            .instr_accounts
            .into_iter()
            .map(|acct| {
                assert!(
                    (acct.index as usize) < accounts.len(),
                    "invariant violation: instruction account index out of bounds"
                );
                AccountMeta {
                    pubkey: accounts[acct.index as usize].0,
                    is_signer: acct.is_signer,
                    is_writable: acct.is_writable,
                }
            })
            .collect();

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

        Self {
            feature_set,
            accounts,
            instruction,
            cu_avail: input.cu_avail,
            rent_collector: RentCollector::default(),
            last_blockhash: Hash::default(),
            lamports_per_signature: 0,
        }
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

pub(crate) fn create_invoke_context_fields(
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

pub fn execute_instr(input: protos::InstrContext) -> Option<protos::InstrEffects> {
    let mut input = InstrContext::from(input);

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
        .configure_next_instruction_for_tests(
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

    let custom_err = if let Err(InstructionError::Custom(code)) = result {
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
    };

    #[allow(clippy::map_identity)]
    let instr_result = result.err().map(|err| {
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
    });

    let modified_accounts: Vec<(Pubkey, Account)> = transaction_context
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
        .collect();

    Some(protos::InstrEffects {
        result: instr_result
            .as_ref()
            .map(instr_err_to_num)
            .unwrap_or_default(),
        custom_err: custom_err.unwrap_or_default(),
        modified_accounts: modified_accounts
            .into_iter()
            .map(|(pubkey, account)| protos::AcctState {
                address: pubkey.to_bytes().to_vec(),
                owner: account.owner.to_bytes().to_vec(),
                lamports: account.lamports,
                data: account.data.to_vec(),
                executable: account.executable,
            })
            .collect(),
        cu_avail,
        return_data,
    })
}
