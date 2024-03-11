#![allow(clippy::missing_safety_doc)]

use prost::Message;
use solana_program_runtime::compute_budget::ComputeBudget;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::loaded_programs::LoadedProgram;
use solana_program_runtime::loaded_programs::LoadedProgramsForTxBatch;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_program_runtime::timings::ExecuteTimings;
use solana_sdk::account::{Account, AccountSharedData};
use solana_sdk::feature_set::FeatureSet;
use solana_sdk::feature_set::*;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::InstructionError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::sysvar::rent::Rent;
use solana_sdk::transaction_context::{InstructionAccount, TransactionAccount, TransactionContext};
use std::collections::HashSet;
use std::ffi::c_int;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/org.solana.sealevel.v1.rs"));
}

static AGAVE_FEATURES: &[Pubkey] = &[
    // Active on all clusters, but not cleaned up.
    pico_inflation::id(),
    warp_timestamp_again::id(),
    disable_fees_sysvar::id(),
    disable_deploy_of_alloc_free_syscall::id(),
    set_exempt_rent_epoch_max::id(),
    incremental_snapshot_only_incremental_hash_calculation::id(),
    relax_authority_signer_check_for_lookup_table_creation::id(),
    commission_updates_only_allowed_in_first_half_of_epoch::id(),
    enable_turbine_fanout_experiments::id(),
    update_hashes_per_tick::id(),
    reduce_stake_warmup_cooldown::id(),
    revise_turbine_epoch_stakes::id(),
    // Active on testnet & devnet.
    libsecp256k1_fail_on_bad_count2::id(),
    enable_bpf_loader_set_authority_checked_ix::id(),
    enable_alt_bn128_syscall::id(),
    switch_to_new_elf_parser::id(),
    vote_state_add_vote_latency::id(),
    require_rent_exempt_split_destination::id(),
    update_hashes_per_tick2::id(),
    update_hashes_per_tick3::id(),
    update_hashes_per_tick4::id(),
    update_hashes_per_tick5::id(),
    validate_fee_collector_account::id(),
    // Active on testnet.
    stake_raise_minimum_delegation_to_1_sol::id(),
    update_hashes_per_tick6::id(),
    // Active on devnet.
    blake3_syscall_enabled::id(),
    curve25519_syscall_enabled::id(),
    libsecp256k1_fail_on_bad_count::id(),
    reject_callx_r10::id(),
    increase_tx_account_lock_limit::id(),
    // Inactive on all clusters.
    zk_token_sdk_enabled::id(),
    enable_partitioned_epoch_reward::id(),
    stake_minimum_delegation_for_rewards::id(),
    stake_redelegate_instruction::id(),
    skip_rent_rewrites::id(),
    loosen_cpi_size_restriction::id(),
    disable_turbine_fanout_experiments::id(),
    enable_big_mod_exp_syscall::id(),
    apply_cost_tracker_during_replay::id(),
    include_loaded_accounts_data_size_in_fee_calculation::id(),
    bpf_account_data_direct_mapping::id(),
    last_restart_slot_sysvar::id(),
    enable_poseidon_syscall::id(),
    timely_vote_credits::id(),
    remaining_compute_units_syscall_enabled::id(),
    enable_program_runtime_v2_and_loader_v4::id(),
    enable_alt_bn128_compression_syscall::id(),
    disable_rent_fees_collection::id(),
    enable_zk_transfer_with_fee::id(),
    drop_legacy_shreds::id(),
    allow_commission_decrease_at_any_time::id(),
    consume_blockstore_duplicate_proofs::id(),
    index_erasure_conflict_duplicate_proofs::id(),
    merkle_conflict_duplicate_proofs::id(),
    enable_zk_proof_from_account::id(),
    curve25519_restrict_msm_length::id(),
    cost_model_requested_write_lock_cost::id(),
    enable_gossip_duplicate_proof_ingestion::id(),
    enable_chained_merkle_shreds::id(),
    // These two were force-activated, but the gate remains on the BPF Loader.
    disable_bpf_loader_instructions::id(),
    deprecate_executable_meta_update_in_bpf_loader::id(),
];

impl From<&proto::FeatureSet> for FeatureSet {
    fn from(input: &proto::FeatureSet) -> Self {
        let mut feature_set = FeatureSet::default();
        let input_features: HashSet<u64> = input.features.iter().copied().collect();

        for id in AGAVE_FEATURES.iter() {
            let discriminator = u64::from_le_bytes(id.to_bytes()[..8].try_into().unwrap());
            if input_features.contains(&discriminator) {
                feature_set.activate(id, 0);
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
    pub program_id: Pubkey,
    pub loader_id: Option<Pubkey>,
    pub feature_set: FeatureSet,
    pub accounts: Vec<(Pubkey, Account)>,
    pub instr_accounts: Vec<InstructionAccount>,
    pub data: Vec<u8>,
    pub cu_avail: u64,
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

        let loader_id = if input.loader_id.is_empty() {
            None
        } else {
            Some(Pubkey::new_from_array(
                input
                    .loader_id
                    .try_into()
                    .map_err(|_| Error::InvalidPubkeyBytes)?,
            ))
        };

        let feature_set = input
            .epoch_context
            .as_ref()
            .and_then(|epoch_ctx| epoch_ctx.features.as_ref())
            .map(|fs| fs.into())
            .unwrap_or_default();

        let accounts = input
            .accounts
            .into_iter()
            .map(|acct_state| acct_state.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let mut instr_accounts =
            Vec::<InstructionAccount>::with_capacity(input.instr_accounts.len());
        for (
            instr_acc_idx,
            proto::InstrAcct {
                index,
                is_signer,
                is_writable,
            },
        ) in input.instr_accounts.into_iter().enumerate()
        {
            if instr_acc_idx > u16::MAX as usize {
                return Err(Error::IntegerOutOfRange);
            }
            if index > u16::MAX as u32 {
                return Err(Error::IntegerOutOfRange);
            }
            instr_accounts.push(InstructionAccount {
                index_in_transaction: index as u16,
                index_in_caller: instr_acc_idx as u16,
                index_in_callee: instr_acc_idx as u16,
                is_signer,
                is_writable,
            });
        }

        Ok(Self {
            program_id,
            loader_id,
            feature_set,
            accounts,
            instr_accounts,
            data: input.data,
            cu_avail: input.cu_avail,
        })
    }
}

fn instr_err_to_num(error: &InstructionError) -> i32 {
    let serialized_err = bincode::serialize(error).unwrap();
    i32::from_le_bytes((&serialized_err[0..4]).try_into().unwrap())
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

fn execute_instr_proto(input: proto::InstrContext) -> Option<proto::InstrEffects> {
    let instr_context = match InstrContext::try_from(input) {
        Ok(context) => context,
        Err(_) => return None,
    };
    let instr_effects = execute_instr(instr_context);
    Some(instr_effects.into())
}

fn load_builtins(cache: &mut LoadedProgramsForTxBatch) {
    cache.replenish(
        solana_system_program::id(),
        Arc::new(LoadedProgram::new_builtin(
            0u64,
            0usize,
            solana_system_program::system_processor::Entrypoint::vm,
        )),
    );
}

fn execute_instr(input: InstrContext) -> InstrEffects {
    // TODO this shouldn't be default
    let mut compute_budget = ComputeBudget::default();
    compute_budget.compute_unit_limit = input.cu_avail;
    let rent = Rent::default();

    let mut transaction_accounts =
        Vec::<TransactionAccount>::with_capacity(input.accounts.len() + 1);
    input
        .accounts
        .into_iter()
        .map(|(pubkey, account)| (pubkey, AccountSharedData::from(account)))
        .for_each(|x| transaction_accounts.push(x));

    let program_idx = if let Some(index) = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == input.program_id)
    {
        index
    } else {
        transaction_accounts.push((
            input.program_id,
            AccountSharedData::from(Account {
                lamports: 10000000,
                data: vec![],
                owner: Pubkey::from_str("NativeLoader1111111111111111111111111111111").unwrap(),
                executable: false,
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

    let sysvar_cache = SysvarCache::default();

    // sigh ... What is this mess?
    let mut programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
    load_builtins(&mut programs_loaded_for_tx_batch);

    let mut programs_modified_by_tx = LoadedProgramsForTxBatch::default();

    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &sysvar_cache,
        None,
        compute_budget,
        &programs_loaded_for_tx_batch,
        &mut programs_modified_by_tx,
        Arc::new(input.feature_set),
        Hash::default(),
        0,
    );

    let program_indices = &[program_idx as u16];

    let mut compute_units_consumed = 0u64;

    let mut timings = ExecuteTimings::default();

    let result = invoke_context.process_instruction(
        &input.data,
        &input.instr_accounts,
        program_indices,
        &mut compute_units_consumed,
        &mut timings,
    );

    InstrEffects {
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
    }
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
            loader_id: Pubkey::default().to_bytes().to_vec(),
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
