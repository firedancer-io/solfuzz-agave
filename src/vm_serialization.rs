use crate::instr::{InstrContext, SnapshotInvokeContext};
use prost::Message;
use protosol::protos;
use solana_compute_budget::compute_budget::SVMTransactionExecutionCost;
use solana_instruction::AccountMeta;
use solana_program_runtime::invoke_context::EnvironmentConfig;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::serialization::serialize_parameters;
use solana_stable_layout::stable_vec::StableVec;
use solana_svm_log_collector::LogCollector;
use std::ffi::c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_vm_serialize_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(instr_context) = protos::InstrContext::decode(in_slice) else {
        return 0;
    };

    let effects = execute_vm_serialize(instr_context);
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    let out_vec = effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };

    1
}

pub fn execute_vm_serialize(input: protos::InstrContext) -> protos::VmSerializationEffects {
    let mut instr_ctx: InstrContext = input.into();

    let program_id = instr_ctx.instruction.program_id;
    let instruction_data = instr_ctx.instruction.data.to_vec();
    let runtime_features = instr_ctx.feature_set.runtime_features();
    let feature_set_snapshot = instr_ctx.feature_set.clone();
    let instruction_accounts_snapshot: StableVec<AccountMeta> = instr_ctx
        .instruction
        .accounts
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();

    let (
        mut transaction_context,
        sysvar_cache,
        mut program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
        environments,
    ) = crate::instr::create_invoke_context_fields(&mut instr_ctx, false).unwrap();

    let instruction_accounts =
        crate::instr::get_instr_accounts(&transaction_context, &instruction_accounts_snapshot);

    let callback_context = SnapshotInvokeContext::new(feature_set_snapshot);

    let environment_config = EnvironmentConfig::new(
        blockhash,
        lamports_per_signature,
        false, /* alpenglow_migration_succeeded */
        &callback_context,
        &runtime_features,
        &environments,
        &sysvar_cache,
    );

    let program_idx = transaction_context
        .find_index_of_account(&program_id)
        .unwrap();

    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(LogCollector::new_ref()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::default(),
    );

    let direct_mapping = invoke_context.get_feature_set().account_data_direct_mapping;
    let virtual_address_space_adjustments = invoke_context
        .get_feature_set()
        .virtual_address_space_adjustments;
    let direct_account_pointers = invoke_context
        .get_feature_set()
        .direct_account_pointers_in_program_input;

    invoke_context
        .transaction_context
        .configure_top_level_instruction_for_tests(
            program_idx,
            instruction_accounts,
            instruction_data,
        )
        .unwrap();

    invoke_context.push().unwrap();

    let caller_instr_ctx = invoke_context
        .transaction_context
        .get_current_instruction_context()
        .unwrap();

    match serialize_parameters(
        &caller_instr_ctx,
        virtual_address_space_adjustments,
        direct_mapping,
        direct_account_pointers,
    ) {
        Ok((aligned_memory, input_memory_regions, acc_metadatas, _instruction_data_offset)) => {
            let serialized_memory_hash =
                crate::utils::fd_hash::fd_hash(0, aligned_memory.as_slice());

            let vm_input_memory_regions = input_memory_regions
                .iter()
                .map(|r| protos::VmInputMemoryRegion {
                    vm_address: r.vm_addr,
                    region_size: r.len,
                    is_writable: r.writable,
                })
                .collect();

            let serialized_account_metadata = acc_metadatas
                .iter()
                .map(|m| protos::VmSerializedAccountMetadata {
                    original_data_len: m.original_data_len as u64,
                    vm_data_addr: m.vm_data_addr,
                    vm_key_addr: m.vm_key_addr,
                    vm_lamports_addr: m.vm_lamports_addr,
                    vm_owner_addr: m.vm_owner_addr,
                })
                .collect();

            protos::VmSerializationEffects {
                has_error: false,
                serialized_memory_hash,
                vm_input_memory_regions,
                serialized_account_metadata,
            }
        }
        Err(_) => protos::VmSerializationEffects {
            has_error: true,
            ..Default::default()
        },
    }
}
