use crate::utils::err_map::elf_err_to_num;
use crate::utils::fd_hash::fd_hash_u64_without_seed;
use crate::utils::fd_hash::fd_hash_without_seed;
use crate::utils::feature_set_from_protos;
use solana_syscalls::create_program_runtime_environment;
use prost::Message;
use protosol::protos::{ElfLoaderCtx, ElfLoaderEffects};
use solana_compute_budget::compute_budget::SVMTransactionExecutionBudget;
use solana_sbpf::{ebpf, elf::Executable};
use std::collections::BTreeSet;
use std::ffi::c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_elf_loader_v1(
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
    let Ok(ctx) = ElfLoaderCtx::decode(in_slice) else {
        return 0;
    };

    let effects = execute_elf_loader(&ctx);

    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    let out_vec = effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };

    1
}

pub fn execute_elf_loader(input: &ElfLoaderCtx) -> ElfLoaderEffects {
    let feature_set = input
        .features
        .as_ref()
        .map(feature_set_from_protos)
        .unwrap_or_default();

    let program_runtime_environment_v1 = create_program_runtime_environment(
        &feature_set.runtime_features(),
        &SVMTransactionExecutionBudget::default(),
        input.deploy_checks,
        std::env::var("ENABLE_VM_TRACING").is_ok(),
    )
    .unwrap();

    // load the elf
    let elf_exec = match Executable::load(
        &input.elf_data,
        std::sync::Arc::clone(&*program_runtime_environment_v1),
    ) {
        Ok(exec) => exec,
        Err(err) => {
            return ElfLoaderEffects {
                err_code: elf_err_to_num(&err) as u32,
                ..Default::default()
            };
        }
    };

    let rodata_hash = fd_hash_without_seed(elf_exec.get_ro_section());

    let (text_vaddr, text_bytes) = elf_exec.get_text_bytes();
    let raw_text_sz = text_bytes.len();

    let mut calldests_map = BTreeSet::<u64>::new();

    let fn_reg = elf_exec.get_function_registry();
    for (_k, v) in fn_reg.iter() {
        let (name, fn_addr) = v;
        let _name_str = std::str::from_utf8(name).unwrap();
        calldests_map.insert(fn_addr as u64);
    }

    let calldests_vec: Vec<u64> = calldests_map.into_iter().collect();
    let calldests_hash = unsafe { fd_hash_u64_without_seed(calldests_vec.as_slice()) };

    ElfLoaderEffects {
        err_code: 0,
        rodata_hash,
        entry_pc: elf_exec.get_entrypoint_instruction_offset() as u64,
        text_off: text_vaddr.saturating_sub(ebpf::MM_BYTECODE_START),
        text_cnt: (raw_text_sz / 8) as u64,
        calldests_hash,
    }
}
