#![allow(clippy::missing_safety_doc)]

mod vm_syscalls;

use lazy_static::lazy_static;
use prost::Message;
use solana_program::clock::Slot;
use solana_program::hash::Hash;
use solana_program_runtime::compute_budget::ComputeBudget;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::loaded_programs::BlockRelation;
use solana_program_runtime::loaded_programs::ForkGraph;
use solana_program_runtime::loaded_programs::LoadedProgram;
use solana_program_runtime::loaded_programs::LoadedProgramsForTxBatch;
use solana_program_runtime::loaded_programs::ProgramCache;
use solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments;
use solana_program_runtime::log_collector::LogCollector;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_program_runtime::timings::ExecuteTimings;
use solana_sdk::account::ReadableAccount;
use solana_sdk::account::{Account, AccountSharedData};
use solana_sdk::clock::Epoch;
use solana_sdk::feature_set::*;
use solana_sdk::fee::FeeStructure;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::instruction::{CompiledInstruction, InstructionError};
use solana_sdk::precompiles::{is_precompile, verify_if_precompile, PrecompileError};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::rent_collector::RentCollector;
use solana_sdk::stable_layout::stable_instruction::StableInstruction;
use solana_sdk::sysvar::clock::Clock;
use solana_sdk::sysvar::epoch_schedule::EpochSchedule;
use solana_sdk::sysvar::rent::Rent;
use solana_sdk::transaction_context::{
    IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
};
use solana_svm::runtime_config::RuntimeConfig;
use solana_svm::transaction_processor::TransactionBatchProcessor;
use solana_svm::transaction_processor::TransactionProcessingCallback;
use solfuzz_agave_macro::load_core_bpf_program;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::c_int;
use std::sync::Arc;
use std::sync::RwLock;
use thiserror::Error;

// macro to rewrite &[IDENTIFIER, ...] to &[feature_u64(IDENTIFIER::id()), ...]
macro_rules! feature_list {
    ($($feature:ident),*$(,)?) => {
        &[$(feature_u64(&$feature::id())),*]
    };
}

static HARDCODED_FEATURES: &[u64] = feature_list![
    secp256k1_program_enabled,
    system_transfer_zero_check,
    native_programs_consume_cu,
    dedupe_config_program_signers,
    vote_stake_checked_instructions,
    require_custodian_for_locked_stake_authorize,
    stake_merge_with_unmatched_credits_observed,
    require_rent_exempt_split_destination,
    vote_authorize_with_seed,
    allow_votes_to_directly_update_vote_state,
    compact_vote_state_updates,
];

static SUPPORTED_FEATURES: &[u64] = feature_list![
    // Active on all clusters, but not cleaned up.
    pico_inflation,
    warp_timestamp_again,
    disable_fees_sysvar,
    disable_deploy_of_alloc_free_syscall,
    set_exempt_rent_epoch_max,
    incremental_snapshot_only_incremental_hash_calculation,
    relax_authority_signer_check_for_lookup_table_creation,
    commission_updates_only_allowed_in_first_half_of_epoch,
    enable_turbine_fanout_experiments,
    update_hashes_per_tick,
    reduce_stake_warmup_cooldown,
    enable_early_verification_of_account_modifications,
    // Active on testnet & devnet.
    libsecp256k1_fail_on_bad_count2,
    enable_bpf_loader_set_authority_checked_ix,
    enable_alt_bn128_syscall,
    switch_to_new_elf_parser,
    vote_state_add_vote_latency,
    update_hashes_per_tick2,
    update_hashes_per_tick3,
    update_hashes_per_tick4,
    update_hashes_per_tick5,
    validate_fee_collector_account,
    // Active on testnet.
    stake_raise_minimum_delegation_to_1_sol,
    update_hashes_per_tick6,
    // Active on devnet.
    blake3_syscall_enabled,
    curve25519_syscall_enabled,
    libsecp256k1_fail_on_bad_count,
    reject_callx_r10,
    increase_tx_account_lock_limit,
    // Inactive on all clusters.
    zk_token_sdk_enabled,
    enable_partitioned_epoch_reward,
    stake_minimum_delegation_for_rewards,
    stake_redelegate_instruction,
    skip_rent_rewrites,
    loosen_cpi_size_restriction,
    disable_turbine_fanout_experiments,
    enable_big_mod_exp_syscall,
    apply_cost_tracker_during_replay,
    include_loaded_accounts_data_size_in_fee_calculation,
    bpf_account_data_direct_mapping,
    last_restart_slot_sysvar,
    enable_poseidon_syscall,
    timely_vote_credits,
    remaining_compute_units_syscall_enabled,
    enable_program_runtime_v2_and_loader_v4,
    enable_alt_bn128_compression_syscall,
    disable_rent_fees_collection,
    enable_zk_transfer_with_fee,
    drop_legacy_shreds,
    allow_commission_decrease_at_any_time,
    consume_blockstore_duplicate_proofs,
    index_erasure_conflict_duplicate_proofs,
    merkle_conflict_duplicate_proofs,
    enable_zk_proof_from_account,
    curve25519_restrict_msm_length,
    cost_model_requested_write_lock_cost,
    enable_gossip_duplicate_proof_ingestion,
    enable_chained_merkle_shreds,
    // These two were force-activated, but the gate remains on the BPF Loader.
    disable_bpf_loader_instructions,
];

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/org.solana.sealevel.v1.rs"));
}

lazy_static! {
    static ref INDEXED_FEATURES: HashMap<u64, Pubkey> = {
        FEATURE_NAMES
            .iter()
            .map(|(pubkey, _)| (feature_u64(pubkey), *pubkey))
            .collect()
    };
}

impl From<&proto::FeatureSet> for FeatureSet {
    fn from(input: &proto::FeatureSet) -> Self {
        let mut feature_set = FeatureSet::default();
        for id in &input.features {
            if let Some(pubkey) = INDEXED_FEATURES.get(id) {
                feature_set.activate(pubkey, 0);
            }
        }
        feature_set
    }
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

    fn get_last_blockhash_and_lamports_per_signature(&self) -> (Hash, u64) {
        let blockhash = Hash::default();
        let lamports_per_signature = 2;
        (blockhash, lamports_per_signature)
    }

    fn get_rent_collector(&self) -> &RentCollector {
        &self.rent_collector
    }

    fn get_feature_set(&self) -> Arc<FeatureSet> {
        Arc::new(self.feature_set.clone())
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
        })
    }
}

fn instr_err_to_num(error: &InstructionError) -> i32 {
    let serialized_err = bincode::serialize(error).unwrap();
    i32::from_le_bytes((&serialized_err[0..4]).try_into().unwrap()) + 1
}

pub struct InstrEffects {
    pub result: Option<InstructionError>,
    pub custom_err: Option<u32>,
    pub modified_accounts: Vec<(Pubkey, Account)>,
    pub cu_avail: u64,
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
                })
                .collect(),
            cu_avail: val.cu_avail,
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

fn load_builtins(cache: &mut LoadedProgramsForTxBatch) -> HashSet<Pubkey> {
    cache.replenish(
        solana_address_lookup_table_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_address_lookup_table_program::processor::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::bpf_loader_deprecated::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::bpf_loader::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::bpf_loader_upgradeable::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_bpf_loader_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_sdk::compute_budget::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_compute_budget_program::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_config_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_config_program::config_processor::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_stake_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_stake_program::stake_instruction::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_system_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_system_program::system_processor::Entrypoint::vm,
        )),
    );
    cache.replenish(
        solana_vote_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_vote_program::vote_processor::Entrypoint::vm,
        )),
    );

    // Will overwrite a builtin if environment variable `CORE_BPF_PROGRAM_ID`
    // is set to a valid program id.
    load_core_bpf_program!();

    // Return builtins as a HashSet
    let mut builtins: HashSet<Pubkey> = HashSet::new();
    builtins.insert(solana_address_lookup_table_program::id());
    builtins.insert(solana_sdk::bpf_loader_deprecated::id());
    builtins.insert(solana_sdk::bpf_loader::id());
    builtins.insert(solana_sdk::bpf_loader_upgradeable::id());
    builtins.insert(solana_sdk::compute_budget::id());
    builtins.insert(solana_config_program::id());
    builtins.insert(solana_stake_program::id());
    builtins.insert(solana_system_program::id());
    builtins.insert(solana_vote_program::id());
    builtins
}

struct DummyForkGraph {
    relation: BlockRelation,
}
impl ForkGraph for DummyForkGraph {
    fn relationship(&self, _a: Slot, _b: Slot) -> BlockRelation {
        self.relation
    }
}

fn execute_instr(input: InstrContext) -> Option<InstrEffects> {
    // TODO this shouldn't be default
    let compute_budget = ComputeBudget {
        compute_unit_limit: input.cu_avail,
        ..ComputeBudget::default()
    };

    let mut sysvar_cache = SysvarCache::default();

    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if let Some(account) = input.accounts.iter().find(|(key, _)| key == pubkey) {
            if account.1.lamports > 0 {
                callbackback(&account.1.data);
            }
        }
    });

    // Set the default clock slot to something arbitrary beyond 0
    // This prevents DelayedVisibility errors when executing BPF programs
    let clock = match sysvar_cache.get_clock() {
        Ok(clock) => (*clock).clone(),
        Err(_) => {
            let mut default_clock = Clock::default();
            default_clock.slot = 10;
            sysvar_cache.set_clock(default_clock.clone());
            default_clock
        }
    };

    let epoch_schedule = match sysvar_cache.get_epoch_schedule() {
        Ok(epoch_schedule) => (*epoch_schedule).clone(),
        Err(_) => {
            let default_epoch_schedule = EpochSchedule::default();
            sysvar_cache.set_epoch_schedule(default_epoch_schedule.clone());
            default_epoch_schedule
        }
    };

    // Add checks for rent boundaries
    let rent: Rent;
    if let Ok(rent_) = sysvar_cache.get_rent() {
        if rent_.lamports_per_byte_year > u32::MAX.into()
            || rent_.exemption_threshold > 999.0
            || rent_.exemption_threshold < 0.0
            || rent_.burn_percent > 100
        {
            return None;
        }
        rent = (*rent_).clone();
    } else {
        let default_rent = Rent::default();
        sysvar_cache.set_rent(default_rent.clone());
        rent = default_rent;
    }

    let mut transaction_accounts =
        Vec::<TransactionAccount>::with_capacity(input.accounts.len() + 1);
    #[allow(deprecated)]
    input
        .accounts
        .iter()
        .map(|(pubkey, account)| (*pubkey, AccountSharedData::from(account.clone())))
        .for_each(|x| transaction_accounts.push(x));

    let program_idx = if let Some(index) = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == input.instruction.program_id)
    {
        index
    } else {
        transaction_accounts.push((
            input.instruction.program_id,
            AccountSharedData::from(Account {
                lamports: 10000000,
                data: b"Solana Program".to_vec(),
                owner: solana_sdk::native_loader::id(),
                executable: true,
                rent_epoch: 0,
            }),
        ));
        transaction_accounts.len() - 1
    };

    let mut transaction_context = TransactionContext::new(
        transaction_accounts.clone(),
        rent,
        compute_budget.max_invoke_stack_height,
        compute_budget.max_instruction_trace_length,
    );

    // sigh ... What is this mess?
    let mut programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
    programs_loaded_for_tx_batch.set_slot_for_tests(clock.slot);
    let loaded_builtins = load_builtins(&mut programs_loaded_for_tx_batch);

    // Skip if the program account is a native program and is not owned by the native loader
    // (Would call the owner instead)
    if loaded_builtins.contains(&transaction_accounts[program_idx].0) && 
        transaction_accounts[program_idx].1.owner() != &solana_sdk::native_loader::id() {
        return None;
    }

    let mut program_cache = ProgramCache::new(Slot::default(), Epoch::default());
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
    program_cache.environments = environments.clone();
    program_cache.upcoming_environments = Some(environments);

    let tx_batch_processor = TransactionBatchProcessor::<DummyForkGraph>::new(
        clock.slot,
        clock.epoch,
        epoch_schedule,
        FeeStructure::default(),
        Arc::<RuntimeConfig>::default(),
        Arc::new(RwLock::new(program_cache)),
        loaded_builtins,
    );

    for acc in &input.accounts {
        if acc.1.executable && programs_loaded_for_tx_batch.find(&acc.0).is_none() {
            if let Some(loaded_program) =
                tx_batch_processor.load_program_with_pubkey(&input, &acc.0, false, 0)
            {
                programs_loaded_for_tx_batch.replenish(acc.0, loaded_program);
            }
        }
    }

    let mut programs_modified_by_tx = LoadedProgramsForTxBatch::default();

    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = sysvar_cache
        .get_recent_blockhashes()
        .ok()
        .and_then(|x| (*x).last().cloned())
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    let log_collector = LogCollector::new_ref();
    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &sysvar_cache,
        Some(log_collector.clone()),
        compute_budget,
        &programs_loaded_for_tx_batch,
        &mut programs_modified_by_tx,
        Arc::new(input.feature_set),
        blockhash,
        lamports_per_signature,
    );

    let program_indices = &[program_idx as u16];

    let mut compute_units_consumed = 0u64;

    let mut timings = ExecuteTimings::default();

    let mut instruction_accounts: Vec<InstructionAccount> =
        Vec::with_capacity(input.instruction.accounts.len());
    for (instruction_account_index, account_meta) in
        input.instruction.accounts.as_ref().iter().enumerate()
    {
        let index_in_transaction = transaction_accounts
            .iter()
            .position(|(key, _account)| *key == account_meta.pubkey)
            .unwrap_or(transaction_accounts.len())
            as IndexOfAccount;
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
    let is_precompile = is_precompile(program_id, |id| invoke_context.feature_set.is_active(id));
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
            &invoke_context.feature_set,
        );
        return Some(InstrEffects {
            custom_err: None,
            result: if let Err(e) = result {
                // Precompiles return PrecompileError instead of InstructionError, and
                // there's no from/into conversion to InstructionError nor to u32.
                // For simplicity, we remap first-first, second-second, etc.
                match e {
                    PrecompileError::InvalidPublicKey => Some(InstructionError::GenericError),
                    PrecompileError::InvalidRecoveryId => Some(InstructionError::InvalidArgument),
                    PrecompileError::InvalidSignature => {
                        Some(InstructionError::InvalidInstructionData)
                    }
                    PrecompileError::InvalidDataOffsets => {
                        Some(InstructionError::InvalidAccountData)
                    }
                    PrecompileError::InvalidInstructionDataSize => {
                        Some(InstructionError::AccountDataTooSmall)
                    }
                }
            } else {
                None
            },
            modified_accounts: vec![],
            cu_avail: input.cu_avail,
        });
    }

    let result = invoke_context.process_instruction(
        &input.instruction.data,
        &instruction_accounts,
        program_indices,
        &mut compute_units_consumed,
        &mut timings,
    );

    Some(InstrEffects {
        custom_err: if let Err(InstructionError::Custom(x)) = result {
            Some(x)
        } else {
            None
        },
        result: result.err(),
        modified_accounts: transaction_context
            .deconstruct_without_keys()
            .unwrap()
            .into_iter()
            .take(transaction_accounts.len() - 1)
            .enumerate()
            .map(|(index, data)| (transaction_accounts[index].0, data.into()))
            .collect(),
        cu_avail: input.cu_avail - compute_units_consumed,
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
pub unsafe extern "C" fn sol_compat_init() {}

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

pub const fn feature_u64(feature: &Pubkey) -> u64 {
    let feature_id = feature.to_bytes();
    feature_id[0] as u64
        | (feature_id[1] as u64) << 8
        | (feature_id[2] as u64) << 16
        | (feature_id[3] as u64) << 24
        | (feature_id[4] as u64) << 32
        | (feature_id[5] as u64) << 40
        | (feature_id[6] as u64) << 48
        | (feature_id[7] as u64) << 56
}

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
                },
                proto::AcctState {
                    address: vec![2u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 0,
                    data: vec![],
                    executable: false,
                    rent_epoch: 0,
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
            txn_context: None,
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
                    },
                    proto::AcctState {
                        address: vec![2u8; 32],
                        owner: vec![0u8; 32],
                        lamports: 1,
                        data: vec![],
                        executable: false,
                        rent_epoch: 0,
                    },
                ],
                cu_avail: 9850u64,
            })
        );
    }
}
