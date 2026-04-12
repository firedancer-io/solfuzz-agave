use crate::utils::{feature_set_from_protos, program::common::build_versioned_message};
use prost::Message;
use protosol::protos::{self, CostContext, CostResult, TxnCostMode};
use solana_cost_model::cost_model::CostModel;
use solana_cost_model::transaction_cost::TransactionCost;
use solana_runtime_transaction::runtime_transaction::RuntimeTransaction;
use solana_signature::Signature;
use solana_transaction::{sanitized::MessageHash, versioned::VersionedTransaction};
use std::ffi::c_int;

fn runtime_transaction_from_proto(
    tx: &protos::SanitizedTransaction,
) -> Option<RuntimeTransaction<solana_transaction::sanitized::SanitizedTransaction>> {
    let message = build_versioned_message(tx.message.as_ref()?);
    let signatures: Vec<Signature> = tx
        .signatures
        .iter()
        .map(|sig| Signature::try_from(sig.as_slice()).ok())
        .collect::<Option<Vec<_>>>()?;
    let versioned_tx = VersionedTransaction {
        signatures,
        message,
    };
    RuntimeTransaction::try_create(
        versioned_tx,
        MessageHash::Compute,
        None,
        solana_message::SimpleAddressLoader::Disabled,
        &std::collections::HashSet::new(),
        true,
        true,
    )
    .ok()
}

fn result_from_transaction_cost(
    cost: TransactionCost<
        '_,
        RuntimeTransaction<solana_transaction::sanitized::SanitizedTransaction>,
    >,
) -> CostResult {
    match cost {
        TransactionCost::SimpleVote { .. } => CostResult {
            has_cost: true,
            signature_cost: cost.signature_cost(),
            write_lock_cost: cost.write_lock_cost(),
            data_bytes_cost: cost.data_bytes_cost() as u64,
            programs_execution_cost: cost.programs_execution_cost(),
            loaded_accounts_data_size_cost: cost.loaded_accounts_data_size_cost(),
            allocated_accounts_data_size: cost.allocated_accounts_data_size(),
            total_cost: cost.sum(),
        },
        TransactionCost::Transaction(details) => CostResult {
            has_cost: true,
            signature_cost: details.signature_cost,
            write_lock_cost: details.write_lock_cost,
            data_bytes_cost: details.data_bytes_cost as u64,
            programs_execution_cost: details.programs_execution_cost,
            loaded_accounts_data_size_cost: details.loaded_accounts_data_size_cost,
            allocated_accounts_data_size: details.allocated_accounts_data_size,
            total_cost: details.sum(),
        },
    }
}

pub fn execute_cost(context: &CostContext) -> Option<CostResult> {
    let tx = runtime_transaction_from_proto(context.tx.as_ref()?)?;
    let feature_set = feature_set_from_protos(context.features.as_ref()?);
    let cost = match TxnCostMode::from_i32(context.mode)? {
        TxnCostMode::Estimate => CostModel::calculate_cost(&tx, &feature_set),
        TxnCostMode::Actual => CostModel::calculate_cost_for_executed_transaction(
            &tx,
            context.actual_programs_execution_cost,
            context
                .actual_loaded_accounts_data_size_bytes
                .try_into()
                .ok()?,
            &feature_set,
        ),
    };
    Some(result_from_transaction_cost(cost))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_txn_cost_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    if out_psz.is_null() || out_ptr.is_null() {
        return 0;
    }
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(context) = CostContext::decode(in_slice) else {
        return 0;
    };
    let Some(result) = execute_cost(&context) else {
        return 0;
    };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    let out_vec = result.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };
    1
}
