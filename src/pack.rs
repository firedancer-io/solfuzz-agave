use crate::proto::{PackComputeBudgetContext, PackComputeBudgetEffects};
use solana_runtime_transaction::instructions_processor::process_compute_budget_instructions;
use solana_sdk::compute_budget;
use solana_sdk::{fee::FeeBudgetLimits, pubkey::Pubkey};
use solana_svm_transaction::instruction::SVMInstruction;
use {prost::Message, std::ffi::c_int};

#[no_mangle]
pub unsafe extern "C" fn sol_compat_pack_compute_budget_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let input = match PackComputeBudgetContext::decode(in_slice) {
        Ok(input) => input,
        Err(_) => return 0,
    };

    let effects = match execute_pack_cbp(input) {
        Some(effects) => effects,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, *out_psz as usize);
    let effects_vec = effects.encode_to_vec();
    if out_slice.len() < effects_vec.len() {
        return 0;
    }

    out_slice[..effects_vec.len()].copy_from_slice(&effects_vec);
    *out_psz = effects_vec.len() as u64;

    1
}

fn execute_pack_cbp(input: PackComputeBudgetContext) -> Option<PackComputeBudgetEffects> {
    let mut svm_instrs: Vec<(&Pubkey, SVMInstruction)> = Vec::new();
    let program_id = compute_budget::id();

    /* Package the instr_datas into a vector of SVM Instructions */
    for (i, instr_data) in input.instr_datas.iter().enumerate() {
        let svm_instr = SVMInstruction {
            program_id_index: i as u8,
            data: instr_data,
            accounts: &[], /* Not used in process_compute_budget_instructions */
        };
        svm_instrs.push((&program_id, svm_instr));
    }

    /* Process SVM instructions, and convert the resulting ComputeBudgetLimits into FeeBudgetLimits
    before extracting the compute unit limit and prioritization fee.
    ComputeBudgetLimits to FeeBudgetLimits conversion is done in compute_budget_limits.rs
    https://github.com/anza-xyz/agave/blob/e7778eb1d6c8007a2240b3c1521f4a521d2aef4e/compute-budget/src/compute_budget_limits.rs#L53 */
    match process_compute_budget_instructions(svm_instrs.into_iter()) {
        Ok(cbp_limits) => {
            let fee_budget_limits: FeeBudgetLimits = cbp_limits.into();
            Some(PackComputeBudgetEffects {
                compute_unit_limit: fee_budget_limits.compute_unit_limit,
                /* prioritization fee (Agave) and rewards (FD) are equivalent
                https://github.com/firedancer-io/firedancer/blob/5e68f9bc5b8aa5ddfff917d27b8089f63adb25c0/src/ballet/pack/fd_compute_budget_program.h#L148-L149 */
                rewards: fee_budget_limits.prioritization_fee,
                heap_sz: cbp_limits.updated_heap_bytes,
                loaded_acct_data_sz: cbp_limits.loaded_accounts_bytes.into(),
            })
        }
        Err(_) => Some(PackComputeBudgetEffects::default()),
    }
}
