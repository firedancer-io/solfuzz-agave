use crate::proto::ElfLoaderEffects;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_program_runtime::solana_rbpf::{ebpf, elf::Executable};
use solana_sdk::{feature_set::*, pubkey::Pubkey};
use solana_program_runtime::compute_budget::ComputeBudget;
use std::collections::{BTreeSet, HashMap, HashSet};


const ACTIVATE_FEATURES: &[Pubkey] = &[
    switch_to_new_elf_parser::id(),
    error_on_syscall_bpf_function_hash_collisions::id(),
    bpf_account_data_direct_mapping::id(),
];


pub fn load_elf(elf_bytes:&[u8]) -> Option<ElfLoaderEffects> {
    let mut feature_set = FeatureSet{
        active: HashMap::new(),
        inactive: HashSet::new(),
    };

    for feature in ACTIVATE_FEATURES.iter() {
        feature_set.activate(feature, 0);
    }

    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &feature_set,
        &ComputeBudget::default(), 
        true,
        false
    ).unwrap();

        // load the elf
    let elf_exec = match Executable::load(elf_bytes, std::sync::Arc::new(program_runtime_environment_v1)) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let ro_section = elf_exec.get_ro_section();
    let (text_vaddr, text_bytes) = elf_exec.get_text_bytes();
    let raw_text_sz = text_bytes.len();

    let mut calldests = BTreeSet::<u64>::new();

    let fn_reg = elf_exec.get_function_registry();
    for (_k, v) in fn_reg.iter() {
        let (_name , fn_addr) = v;
        let _name_str = std::str::from_utf8(_name).unwrap();
        calldests.insert(fn_addr as u64);
    }

    Some(
        ElfLoaderEffects {
            rodata: ro_section.to_vec(),
            rodata_sz: ro_section.len() as u64,
            entry_pc: elf_exec.get_entrypoint_instruction_offset() as u64,
            text: Vec::new(),
            text_off: (text_vaddr - ebpf::MM_PROGRAM_START) as u64, // FIXME: assumes ro offset is 0
            text_cnt: (raw_text_sz/8) as u64,
            calldests: calldests.into_iter().collect(),
        })
    
}
