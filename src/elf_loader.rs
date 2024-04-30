use crate::proto::ElfLoaderEffects;
use prost::Message;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_program_runtime::solana_rbpf::{ebpf, elf::Executable};
use solana_sdk::feature_set::*;
use solana_program_runtime::compute_budget::ComputeBudget;

use std::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_elf_loader_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int { 
    let elf_loader_effects = match load_elf(
        std::slice::from_raw_parts(in_ptr, in_sz as usize),
    ) {
        Some(v) => v,
        None => return 0,
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

fn load_elf(elf_bytes:&[u8]) -> Option<ElfLoaderEffects> {
    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &FeatureSet::all_enabled(),
        &ComputeBudget::default(), 
        false, 
        false
    ).unwrap();
    let elf_exec = match Executable::load(elf_bytes, std::sync::Arc::new(program_runtime_environment_v1)) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let ro_section = elf_exec.get_ro_section();
    let (text_vaddr, text_bytes) = elf_exec.get_text_bytes();
    let text_sz = text_bytes.len();

    Some(
        ElfLoaderEffects {
            rodata: ro_section.to_vec(),
            rodata_sz: ro_section.len() as u64,
            entry_pc: elf_exec.get_entrypoint_instruction_offset() as u64,
            text_off: (text_vaddr - ebpf::MM_PROGRAM_START) as u64, // FIXME: assumes ro offset is 0
            text_cnt: (text_sz/8) as u64
        })
    
}
