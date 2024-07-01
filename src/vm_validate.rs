use crate::elf_loader::ACTIVATE_FEATURES;
use crate::proto::{FullVmContext, ValidateVmEffects};
use prost::Message;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_program_runtime::solana_rbpf::error::EbpfError;
use solana_program_runtime::solana_rbpf::program::FunctionRegistry;
use solana_program_runtime::solana_rbpf::verifier::RequisiteVerifier;
use solana_program_runtime::solana_rbpf::{elf::Executable, verifier::VerifierError};
use solana_sdk::feature_set::*;
use std::collections::{HashMap, HashSet};
use std::ffi::c_int;

fn get_fd_err_code(ebpf_err: EbpfError) -> i32 {
    let ver_err = match ebpf_err {
        EbpfError::VerifierError(err) => err,
        _ => return -1,
    };
    // https://github.com/firedancer-io/firedancer/blob/f878e448e5511c3600e2dd6360a4f06ce793af6f/src/flamenco/vm/fd_vm_base.h#L67
    match ver_err {
        VerifierError::NoProgram => -6,
        VerifierError::DivisionByZero(_) => -18,
        VerifierError::UnknownOpCode(_, _) => -25,
        VerifierError::InvalidSourceRegister(_) => -26,
        VerifierError::InvalidDestinationRegister(_) => -27,
        VerifierError::CannotWriteR10(_) => -27, // FD treats this the same as InvalidDestinationRegister
        VerifierError::InfiniteLoop(_) => -28,   // Not checked here (nor in FD)
        VerifierError::JumpOutOfCode(_, _) => -29,
        VerifierError::JumpToMiddleOfLDDW(_, _) => -30,
        VerifierError::UnsupportedLEBEArgument(_) => -31,
        VerifierError::LDDWCannotBeLast => -32,
        VerifierError::IncompleteLDDW(_) => -33,
        VerifierError::InvalidRegister(_) => -35,
        VerifierError::ShiftWithOverflow(_, _, _) => -37,
        VerifierError::ProgramLengthNotMultiple => -38,
        _ => -1,
    }
}

fn gen_feature_set() -> FeatureSet {
    let mut feature_set = FeatureSet {
        active: HashMap::new(),
        inactive: HashSet::new(),
    };

    for feature in ACTIVATE_FEATURES.iter() {
        feature_set.activate(feature, 0);
    }
    feature_set
}

pub fn validate_vm_text(text_bytes: &[u8], feature_set: &FeatureSet) -> Option<ValidateVmEffects> {
    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        feature_set,
        &ComputeBudget::default(),
        false, // doesn't matter since bytes are "loaded"
        false, // doesn't matter
    )
    .unwrap();

    let exec = match Executable::new_from_text_bytes(
        text_bytes,
        std::sync::Arc::new(program_runtime_environment_v1),
        solana_program_runtime::solana_rbpf::program::SBPFVersion::V1,
        FunctionRegistry::default(),
    ) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let result = match exec.verify::<RequisiteVerifier>() {
        Ok(_) => 0,
        Err(err) => get_fd_err_code(err),
    };

    Some(ValidateVmEffects {
        result,
        success: result == 0,
    })
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_validate_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let ctx = match FullVmContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let vm_ctx = match ctx.vm_ctx {
        Some(vm_ctx) => vm_ctx,
        None => return 0,
    };
    let feature_set: FeatureSet = ctx
        .features
        .as_ref()
        .map(|fs| fs.into())
        .unwrap_or(gen_feature_set());

    let text_len = vm_ctx.rodata_text_section_length as usize;
    let text_off = vm_ctx.rodata_text_section_offset as usize;
    // Rust panics if text_off + text_len overflows (or is out of range),
    // but we want to return an error instead.
    let validate_vm_effects = match vm_ctx
        .rodata
        .get(text_off..text_off.saturating_add(text_len))
    {
        Some(bytes) => {
            let validate_vm_effects = validate_vm_text(bytes, &feature_set);
            match validate_vm_effects {
                Some(context) => context,
                None => return 0,
            }
        }
        None => ValidateVmEffects {
            result: -36, // FD error code for invalid text section
            success: false,
        },
    };
    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_bytes = validate_vm_effects.encode_to_vec();
    if out_bytes.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_bytes.len()].copy_from_slice(&out_bytes);
    *out_psz = out_bytes.len() as u64;
    1
}
