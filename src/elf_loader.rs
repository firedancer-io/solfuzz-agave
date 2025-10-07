use crate::proto;
use crate::proto::{ElfLoaderCtx, ElfLoaderEffects};
use crate::utils::err_map::elf_err_to_num;
use agave_feature_set::*;
use agave_syscalls::create_program_runtime_environment_v1;
use prost::Message;
use solana_compute_budget::compute_budget::SVMTransactionExecutionBudget;
use solana_sbpf::{ebpf, elf::Executable};
use std::collections::BTreeSet;

use std::ffi::c_int;

pub fn load_elf(
    elf_bytes: &[u8],
    features: Option<&proto::FeatureSet>,
    deploy_checks: bool,
) -> Option<ElfLoaderEffects> {
    let feature_set = FeatureSet::from(features.unwrap_or(&proto::FeatureSet::default()));
    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &feature_set.runtime_features(),
        &SVMTransactionExecutionBudget::default(),
        deploy_checks,
        std::env::var("ENABLE_VM_TRACING").is_ok(),
    )
    .unwrap();

    let mut elf_effects = ElfLoaderEffects::default();

    // load the elf
    let elf_exec = match Executable::load(
        elf_bytes,
        std::sync::Arc::new(program_runtime_environment_v1),
    ) {
        Ok(exec) => exec,
        Err(err) => {
            return Some(ElfLoaderEffects {
                error: elf_err_to_num(&err),
                ..Default::default()
            });
        }
    };

    let ro_section = elf_exec.get_ro_section();
    let (text_vaddr, text_bytes) = elf_exec.get_text_bytes();
    let raw_text_sz = text_bytes.len();

    let mut calldests = BTreeSet::<u64>::new();

    let fn_reg = elf_exec.get_function_registry();
    for (_k, v) in fn_reg.iter() {
        let (name, fn_addr) = v;
        let _name_str = std::str::from_utf8(name).unwrap();
        calldests.insert(fn_addr as u64);
    }

    elf_effects.error = 0;
    elf_effects.rodata = ro_section.to_vec();
    elf_effects.rodata_sz = ro_section.len() as u64;
    elf_effects.entry_pc = elf_exec.get_entrypoint_instruction_offset() as u64;
    elf_effects.text_off = text_vaddr.saturating_sub(ebpf::MM_RODATA_START);
    elf_effects.text_cnt = (raw_text_sz / 8) as u64;
    elf_effects.calldests = calldests.into_iter().collect();
    Some(elf_effects)
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_elf_loader_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_sz == 0 {
        return 0;
    }

    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let Ok(elf_loader_ctx) = ElfLoaderCtx::decode(in_slice) else {
        return 0;
    };

    if elf_loader_ctx.encoded_len() != in_sz as usize {
        return 0;
    }

    let Some(elf_loader_effects) = execute_elf_loader(&elf_loader_ctx) else {
        return 0;
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = elf_loader_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;
    1
}

pub fn execute_elf_loader(input: &ElfLoaderCtx) -> Option<ElfLoaderEffects> {
    let elf_bytes = input.elf.as_ref()?.data.as_slice();
    load_elf(elf_bytes, input.features.as_ref(), input.deploy_checks)
}
