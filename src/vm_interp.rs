use crate::{
    load_builtins,
    proto::{SyscallContext, SyscallEffects, VmContext},
    InstrContext,
};
use bincode::Error;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_log_collector::LogCollector;
use solana_program_runtime::{invoke_context::{EnvironmentConfig, InvokeContext}, loaded_programs::ProgramCacheForTxBatch, solana_rbpf::{
    declare_builtin_function, ebpf, elf::Executable, error::StableResult, interpreter::Interpreter, memory_region::{MemoryMapping, MemoryRegion}, program::{self, BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion}, verifier::RequisiteVerifier, vm::{Config, ContextObject, EbpfVm}
}, sysvar_cache::SysvarCache};
use prost::Message;
use solana_sdk::{feature_set::{add_compute_budget_program, FeatureSet}, hash::Hash, rent::Rent, transaction_context::TransactionContext};
use std::{collections::{HashMap, HashSet}, ffi::c_int, sync::Arc};

declare_builtin_function!(
    SyscallStub,
    fn rust(
        _invoke_context: &mut InvokeContext,
        _hash_addr: u64,
        _recovery_id_val: u64,
        _signature_addr: u64,
        _result_addr: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error>{
        // TODO: deduct CUs?
        Ok(0)
    }
);

const STACK_SIZE: usize = 524288;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_interp_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let syscall_context = match SyscallContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };

    let syscall_effects = match execute_vm_interp(syscall_context) {
        Some(v) => v,
        None => return 0,
    };
    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = syscall_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

fn execute_vm_interp(syscall_context: SyscallContext) -> Option<SyscallEffects> {
    // let instr_ctx:InstrContext = syscall_context.instr_ctx?.try_into().ok()?;


    let feature_set = FeatureSet {
        active: HashMap::new(),
        inactive: HashSet::new(),
    };
    
    let compute_budget = ComputeBudget {
        compute_unit_limit: syscall_context.instr_ctx?.cu_avail,
        ..ComputeBudget::default()
    };

    let unstubbed_runtime = create_program_runtime_environment_v1(
        &feature_set,
        &compute_budget,
        false,
        false,
    )
    .unwrap();

    // stub syscalls
    let syscall_reg = unstubbed_runtime.get_function_registry();
    let mut stubbed_syscall_reg = FunctionRegistry::<BuiltinFunction<InvokeContext>>::default();

    for (key, (name, _)) in syscall_reg.iter() {
        stubbed_syscall_reg.register_function(key, name, SyscallStub::vm).unwrap();
    }
    let program_runtime_environment_v1 = BuiltinProgram::new_loader(unstubbed_runtime.get_config().clone(), stubbed_syscall_reg);

    let sbpf_version: SBPFVersion = SBPFVersion::V1;
    let loader = std::sync::Arc::new(program_runtime_environment_v1);

    
    // Setup InvokeContext
    let mut txn_ctx = TransactionContext::new(
        vec![],
        Rent::default(),
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length
    );
    
    let sysvar = SysvarCache::default();
    let environment_config = EnvironmentConfig::new(
        Hash::default(),
        None,
        None,
        Arc::new(FeatureSet::all_enabled()),
        0,
        &sysvar,
    );
    
    let mut prog_cache = ProgramCacheForTxBatch::default();
    let mut invoke_context = InvokeContext::new(
        &mut txn_ctx,
        &mut prog_cache,
        environment_config, 
        Some(LogCollector::new_ref()), 
        compute_budget
    );
    
    
    // setup memory
    let vm_ctx = syscall_context.vm_ctx.unwrap();
    let function_registry = setup_internal_fn_registry(&vm_ctx);
    
    let rodata = &vm_ctx.rodata;
    let mut stack = vec![0; STACK_SIZE];
    let heap_max = vm_ctx.heap_max;
    let mut heap = vec![0; heap_max as usize];
    let mut regions = vec![
        MemoryRegion::new_readonly(&rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
    ];

    let mut input_data_regions = vm_ctx.input_data_regions.clone();
    for input_data_region in &mut input_data_regions {
        if input_data_region.is_writable {
            regions.push(MemoryRegion::new_writable(
                input_data_region.content.as_mut_slice(),
                ebpf::MM_INPUT_START + input_data_region.offset,
            ));
        } else {
            regions.push(MemoryRegion::new_readonly(
                input_data_region.content.as_slice(),
                ebpf::MM_INPUT_START + input_data_region.offset,
            ));
        }
    }
    let config = &Config {
        aligned_memory_mapping: true,
        enable_sbpf_v2: true,
        ..Config::default()
    };
    
    let memory_mapping = match MemoryMapping::new(regions, config, &sbpf_version) {
        Ok(mapping) => mapping,
        Err(_) => return None,
    };

    
    let mut vm = EbpfVm::new(
        loader.clone(),
        &sbpf_version,
        &mut invoke_context,
        memory_mapping,
        STACK_SIZE
    );
    
    // setup registers
    vm.registers[0] = vm_ctx.r0;
    vm.registers[1] = vm_ctx.r1;
    vm.registers[2] = vm_ctx.r2;
    vm.registers[3] = vm_ctx.r3;
    vm.registers[4] = vm_ctx.r4;
    vm.registers[5] = vm_ctx.r5;
    vm.registers[6] = vm_ctx.r6;
    vm.registers[7] = vm_ctx.r7;
    vm.registers[8] = vm_ctx.r8;
    vm.registers[9] = vm_ctx.r9;
    vm.registers[10] = vm_ctx.r10;
    // vm.registers[11] = vm_ctx.r11; set by interpreter

    let executable = Executable::from_text_bytes(
        &vm_ctx.rodata,
        loader,
        sbpf_version.clone(),
        function_registry
    ).unwrap();

    match executable.verify::<RequisiteVerifier>(){
        Err(_) => return Some( SyscallEffects{
            error: -1,
            ..Default::default()
        }),
        _ => {}
    }

    let (_, result) = vm.execute_program(
        &executable,
        true /* Interpreted */
    );
    
    Some(SyscallEffects {
        error: match result {
            StableResult::Ok(_) => 0,
            StableResult::Err(_) => -1, //TODO: map
        },
        r0: match result {
            StableResult::Ok(n) => n,
            StableResult::Err(_) => 0,
        },
        cu_avail: vm.context_object_pointer.get_remaining(),
        frame_count: vm.call_depth,
        heap,
        stack,
        // inputdata: input_data_regions
        //     .iter()
        //     .flat_map(|region| region.content.clone())
        //     .collect(),
        inputdata: vec![],
        log: vec![],
        pc: vm.registers[11] as u64, // FIXME: is this correct?
    })
}

fn setup_internal_fn_registry(vm_ctx: &VmContext) -> FunctionRegistry<usize> {
    let mut fn_reg = FunctionRegistry::default();
    
    // register entry point
    
    let _ = fn_reg.register_function(
        ebpf::hash_symbol_name(b"entrypoint"),
        b"entrypoint",
        vm_ctx.entry_pc as usize,
    );

    let call_whitelist = &vm_ctx.call_whitelist;
    for (byte_idx, byte) in call_whitelist.iter().enumerate() {
        for bit_idx in 0..8 {
            if (byte & (1 << bit_idx)) != 0 {
                let pc = byte_idx * 8 + bit_idx;
                let _ = fn_reg.register_function(
                    ebpf::hash_symbol_name(&u64::to_be_bytes(pc as u64)), // FIXME: is this correct?
                    b"fn",
                    pc,
                );
            }
        }
    }
    
    

    fn_reg
}

// fn stub_syscalls<'a>( runtime_env : &BuiltinProgram<InvokeContext>)
//      -> BuiltinProgram<InvokeContext<'a>> {
//     // let &syscall_reg = runtime_env.get_function_registry();
//     // let mut new_syscall_reg = FunctionRegistry::<BuiltinFunction<InvokeContext>>::default();

//     // for (key, (name, _)) in syscall_reg.iter() {
//     //     new_syscall_reg.register_function(key, name, SyscallStub::vm).unwrap();
//     // }

//     // BuiltinProgram::new_loader(runtime_env.get_config().clone(), new_syscall_reg)
// }
