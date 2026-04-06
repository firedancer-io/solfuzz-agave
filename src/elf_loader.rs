use crate::context_generated;
use crate::elf_generated;
use crate::utils::err_map::elf_err_to_num;
use crate::utils::fd_hash::fd_hash_u64_without_seed;
use crate::utils::fd_hash::fd_hash_without_seed;
use crate::utils::program::common_flatbuffers::feature_set_from_fbs;
use agave_syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::SVMTransactionExecutionBudget;
use solana_sbpf::{ebpf, elf::Executable};
use std::collections::BTreeSet;

pub fn load_elf(
    elf_bytes: &[u8],
    builder: &mut flatbuffers::FlatBufferBuilder,
    features: &context_generated::FeatureSet,
    deploy_checks: bool,
) {
    let feature_set = feature_set_from_fbs(features);

    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &feature_set.runtime_features(),
        &SVMTransactionExecutionBudget::default(),
        deploy_checks,
        std::env::var("ENABLE_VM_TRACING").is_ok(),
    )
    .unwrap();

    // load the elf
    let elf_exec = match Executable::load(
        elf_bytes,
        std::sync::Arc::new(program_runtime_environment_v1),
    ) {
        Ok(exec) => exec,
        Err(err) => {
            let effects = elf_generated::ELFLoaderEffects::create(
                builder,
                &elf_generated::ELFLoaderEffectsArgs {
                    err_code: elf_err_to_num(&err),
                    ..Default::default()
                },
            );
            builder.finish_minimal(effects);
            return;
        }
    };

    let rodata_hash_u64 = fd_hash_without_seed(elf_exec.get_ro_section());
    let rodata_hash = context_generated::XXHash::new(&rodata_hash_u64.to_le_bytes());

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
    let calldests_hash_u64 = unsafe { fd_hash_u64_without_seed(calldests_vec.as_slice()) };
    let calldests_hash = context_generated::XXHash::new(&calldests_hash_u64.to_le_bytes());

    let effects = elf_generated::ELFLoaderEffects::create(
        builder,
        &elf_generated::ELFLoaderEffectsArgs {
            err_code: 0,
            rodata_hash: Some(&rodata_hash),
            entry_pc: elf_exec.get_entrypoint_instruction_offset() as u64,
            text_off: text_vaddr.saturating_sub(ebpf::MM_BYTECODE_START),
            text_cnt: (raw_text_sz / 8) as u64,
            calldests_hash: Some(&calldests_hash),
        },
    );
    builder.finish_minimal(effects);
}

pub fn execute_elf_loader(
    input: &elf_generated::ELFLoaderCtx,
    builder: &mut flatbuffers::FlatBufferBuilder,
) {
    let elf_bytes = input.elf_data().bytes();
    let features = input.features();
    load_elf(elf_bytes, builder, &features, input.deploy_checks());
}
