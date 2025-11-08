use crate::context_generated;
use crate::elf_generated;
use crate::utils::err_map::elf_err_to_num;
use crate::utils::fd_hash::fd_hash;
use crate::utils::fd_hash::fd_hash_u64;
use agave_feature_set::*;
use agave_syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::SVMTransactionExecutionBudget;
use solana_sbpf::{ebpf, elf::Executable};
use std::collections::BTreeSet;

pub fn load_elf<'ctx, 'buf>(
    elf_bytes: &[u8],
    builder: &mut flatbuffers::FlatBufferBuilder<'buf>,
    features: &context_generated::FeatureSet<'ctx>,
    deploy_checks: bool,
) {
    let feature_set = FeatureSet::from(features);

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

    let rodata_hash = fd_hash(elf_exec.get_ro_section());
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
    let calldests_hash = unsafe { fd_hash_u64(calldests_vec.as_slice()) };

    let effects = elf_generated::ELFLoaderEffects::create(
        builder,
        &elf_generated::ELFLoaderEffectsArgs {
            err_code: 0,
            rodata_hash,
            entry_pc: elf_exec.get_entrypoint_instruction_offset() as u64,
            text_off: text_vaddr.saturating_sub(ebpf::MM_RODATA_START),
            text_cnt: (raw_text_sz / 8) as u64,
            calldests_hash,
        },
    );
    builder.finish_minimal(effects);
}

pub fn execute_elf_loader<'ctx, 'buf>(
    input: &elf_generated::ELFLoaderCtx<'ctx>,
    builder: &mut flatbuffers::FlatBufferBuilder<'buf>,
) {
    let elf_bytes = input.elf_data().bytes();
    let features = input.features();
    load_elf(elf_bytes, builder, &features, input.deploy_checks());
}
