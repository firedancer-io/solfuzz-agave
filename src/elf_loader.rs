use crate::proto::{ElfLoaderCtx, ElfLoaderEffects};
use prost::Message;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_program_runtime::solana_rbpf::{ebpf, elf::Executable};
use solana_sdk::{feature_set::*, pubkey::Pubkey};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::c_int;

pub const ACTIVATE_FEATURES: &[Pubkey] = &[
    switch_to_new_elf_parser::id(),
    error_on_syscall_bpf_function_hash_collisions::id(),
    bpf_account_data_direct_mapping::id(),
];

pub fn load_elf(elf_bytes: &[u8], deploy_checks: bool) -> Option<ElfLoaderEffects> {
    let mut feature_set = FeatureSet {
        active: HashMap::new(),
        inactive: HashSet::new(),
    };

    for feature in ACTIVATE_FEATURES.iter() {
        feature_set.activate(feature, 0);
    }

    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &feature_set,
        &ComputeBudget::default(),
        deploy_checks,
        false,
    )
    .unwrap();

    let mut elf_effects = ElfLoaderEffects::default();

    // load the elf
    let elf_exec = match Executable::load(
        elf_bytes,
        std::sync::Arc::new(program_runtime_environment_v1),
    ) {
        Ok(v) => v,
        Err(_) => return Some(elf_effects),
    };

    let ro_section = elf_exec.get_ro_section();
    let (text_vaddr, text_bytes) = elf_exec.get_text_bytes();
    let raw_text_sz = text_bytes.len();

    let mut calldests = BTreeSet::<u64>::new();

    let fn_reg = elf_exec.get_function_registry();
    for (_k, v) in fn_reg.iter() {
        let (_name, fn_addr) = v;
        let _name_str = std::str::from_utf8(_name).unwrap();
        calldests.insert(fn_addr as u64);
    }

    elf_effects.rodata = ro_section.to_vec();
    elf_effects.rodata_sz = ro_section.len() as u64;
    elf_effects.entry_pc = elf_exec.get_entrypoint_instruction_offset() as u64;
    elf_effects.text_off = text_vaddr - ebpf::MM_RODATA_START;
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
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let elf_loader_ctx = match ElfLoaderCtx::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };

    let elf_loader_effects = match execute_elf_loader(elf_loader_ctx) {
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

pub fn execute_elf_loader(input: ElfLoaderCtx) -> Option<ElfLoaderEffects> {
    let mut elf_bytes = match input.elf {
        Some(elf) => elf.data,
        None => return None,
    };

    if elf_bytes.len() != input.elf_sz as usize {
        // setup elf bytes to match the size
        elf_bytes.resize(input.elf_sz as usize, 0);
    }

    let elf_loader_effects = match load_elf(elf_bytes.as_slice(), input.deploy_checks) {
        Some(v) => v,
        None => return None,
    };

    Some(elf_loader_effects)
}
