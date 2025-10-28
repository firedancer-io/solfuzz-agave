use crate::instr_flatbuffers;
use crate::utils::err_map_flatbuffers;
use crate::utils::vm::mem_regions_flatbuffers::vec_rtrim_zeros;
use crate::utils::vm::{mem_regions_flatbuffers, STACK_SIZE};
// feature removed from feature set surface in 3.0; direct mapping toggled via SVMFeatureSet flags
use crate::vm_generated;
use bincode::Error;
use solana_compute_budget::compute_budget::SVMTransactionExecutionCost;
use solana_program_runtime::serialization::serialize_parameters;
use solana_program_runtime::{
    invoke_context::{EnvironmentConfig, InvokeContext},
    mem_pool::VmMemoryPool,
};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    declare_builtin_function,
    ebpf::{self, HOST_ALIGN},
    elf::Executable,
    error::{EbpfError, StableResult},
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::TraceLogEntry,
    verifier::RequisiteVerifier,
    vm::{ContextObject, EbpfVm},
};
use solana_svm_log_collector::LogCollector;

declare_builtin_function!(
    SyscallStub,
    fn rust(
        _invoke_context: &mut TestContextObject,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        // TODO: deduct CUs?
        Ok(0)
    }
);

/// Simple instruction meter for testing
#[derive(Debug, Clone, Default)]
pub struct TestContextObject {
    /// Contains the register state at every instruction in order of execution
    pub trace_log: Vec<TraceLogEntry>,
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

impl ContextObject for TestContextObject {
    fn trace(&mut self, state: [u64; 12]) {
        self.trace_log.push(state);
    }

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TestContextObject {
    /// Initialize with instruction meter
    pub fn new(remaining: u64) -> Self {
        Self {
            trace_log: Vec::new(),
            remaining,
        }
    }

    /// Compares an interpreter trace and a JIT trace.
    ///
    /// The log of the JIT can be longer because it only validates the instruction meter at branches.
    pub fn compare_trace_log(interpreter: &Self, jit: &Self) -> bool {
        let interpreter = interpreter.trace_log.as_slice();
        let mut jit = jit.trace_log.as_slice();
        if jit.len() > interpreter.len() {
            jit = &jit[0..interpreter.len()];
        }
        interpreter == jit
    }
}

/* Set to true to make debugging easier

WARNING: CU validation works differently in the
interpreter vs. JIT. You may get CU mismatches you
otherwise wouldn't see when fuzzing against the JIT.

FD targets conformance with the JIT, not interpreter. */
const USE_INTERPRETER: bool = false;

/* Set to true to dump registers[0..12] of every instruction
execution (dumped after execution). Please leave disabled
for fuzzing. */
const ENABLE_TRACE_DUMP: bool = false;

/* This sets up a function registry based on a Firedancer-loaded SBPF program.
The key difference is call immediates are hashed based on their target pc,
not the function symbol. Firedancer maintains a bit vector of all valid call
destinations[1], which the interpreter uses during the CALL_IMM instruction.

To mimic that behavior here, we iterate through the valid call destinations
in vm_ctx.call_whitelist, and register the pc hash as an entry in the registry.

This effectively behaves the same as the FD bit vector, but with some technical
differences that may cause issues. Most notably, FunctionRegistry operates as
a AHashMap, while FD's bit vector is a simple array. Out of bounds queries are
non-issue here, but require explicit handling in FD. This causes a slight
difference in error checks in CALL_IMM, which we handle in process_result.

[1](https://github.com/firedancer-io/firedancer/blob/93cea434dfe2f728f2ab4746590972644c06b863/src/ballet/sbpf/fd_sbpf_loader.h#L27). */
fn setup_internal_fn_registry(
    vm_ctx: &vm_generated::VmContext,
    sbpf_version: SBPFVersion,
) -> FunctionRegistry<usize> {
    let mut fn_reg = FunctionRegistry::default();
    let max_pc = vm_ctx.rodata().len() / 8;

    // register entry point
    let entry_pc = (vm_ctx.entry_pc() as usize).min(max_pc.saturating_sub(1));
    let hash = if sbpf_version.enable_stricter_elf_headers() {
        entry_pc as u32
    } else {
        ebpf::hash_symbol_name(b"entrypoint")
    };
    let _ = fn_reg.register_function(hash, b"entrypoint", entry_pc);

    let call_whitelist = &vm_ctx.calldests().bytes();
    for (byte_idx, byte) in call_whitelist.iter().enumerate() {
        for bit_idx in 0..8 {
            if (byte & (1 << bit_idx)) != 0 {
                let pc = byte_idx.saturating_mul(8).saturating_add(bit_idx);
                // ignore invalid pc, i.e. assume the test was set up correctly.
                // registering fn beyond max_pc segfaults inside the JIT.
                if pc < max_pc {
                    let hash = if sbpf_version.enable_stricter_elf_headers() {
                        pc as u32
                    } else {
                        ebpf::hash_symbol_name(&u64::to_le_bytes(pc as u64))
                    };
                    let _ = fn_reg.register_function(hash, b"fn", pc);
                }
            }
        }
    }

    // https://github.com/anza-xyz/sbpf/blob/v0.11.1/src/elf.rs#L529
    // in vm v3, the function at 0 is always registered
    if sbpf_version.enable_stricter_elf_headers() {
        let _ = fn_reg.register_function(0, b"fn0", 0);
    }

    fn_reg
}

// We are actually executing the JIT-compiled program here
pub fn execute_vm_interp<'a>(
    syscall_context: &vm_generated::SyscallContext<'a>,
    builder: &mut flatbuffers::FlatBufferBuilder<'a>,
) {
    let mut instr_ctx = instr_flatbuffers::InstrContext::from(&syscall_context.instr_ctx());

    let vm_ctx = syscall_context.vm_ctx();
    let sbpf_version = match vm_ctx.sbpf_version() {
        1 => SBPFVersion::V1,
        2 => SBPFVersion::V2,
        3 => SBPFVersion::V3,
        _ => SBPFVersion::V0,
    };

    let (
        mut transaction_context,
        sysvar_cache,
        mut program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
    ) = instr_flatbuffers::create_invoke_context_fields(&mut instr_ctx);

    let instr = &instr_ctx.instruction;

    let log_collector = LogCollector::new_ref();
    let instr_accounts = crate::get_instr_accounts(&transaction_context, &instr.accounts);
    let runtime_features = instr_ctx.feature_set.runtime_features();

    let mut invoke_ctx = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        EnvironmentConfig::new(
            blockhash,
            lamports_per_signature,
            &instr_ctx,
            &runtime_features,
            &sysvar_cache,
        ),
        Some(log_collector.clone()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::default(),
    );

    let program_idx = invoke_ctx
        .transaction_context
        .find_index_of_account(&instr_ctx.instruction.program_id)
        .expect("Invariant violation: program account not found in transaction context");

    let direct_mapping = invoke_ctx.get_feature_set().account_data_direct_mapping;
    let stricter_abi_and_runtime_constraints = invoke_ctx
        .get_feature_set()
        .stricter_abi_and_runtime_constraints;
    let mask_out_rent_epoch_in_vm_serialization = invoke_ctx
        .get_feature_set()
        .mask_out_rent_epoch_in_vm_serialization;

    invoke_ctx
        .transaction_context
        .configure_next_instruction_for_tests(program_idx, instr_accounts, &instr.data)
        .unwrap();

    /* TODO: figure out how to bypass this check in the fuzzer, or maybe
    return an error code of -1 */
    invoke_ctx
        .push()
        .expect("Invariant violation: stack frame push should not fail");

    let caller_instr_ctx = invoke_ctx
        .transaction_context
        .get_current_instruction_context()
        .expect("Instruction call stack was not properly initialized");
    let (_aligned_memory, input_memory_regions, acc_metadatas) = serialize_parameters(
        &caller_instr_ctx,
        stricter_abi_and_runtime_constraints,
        direct_mapping,
        mask_out_rent_epoch_in_vm_serialization,
    )
    .unwrap();

    let mut config = invoke_ctx
        .program_cache_for_tx_batch
        .environments
        .program_runtime_v1
        .get_config()
        .clone();
    config.enable_instruction_tracing = true;
    config.enabled_sbpf_versions = SBPFVersion::V0..=sbpf_version;

    invoke_ctx
        .set_syscall_context(solana_program_runtime::invoke_context::SyscallContext {
            allocator: solana_program_runtime::invoke_context::BpfAllocator::new(vm_ctx.heap_max()),
            accounts_metadata: acc_metadatas, // TODO: accounts metadata for direct mapping support
            trace_log: Vec::new(),
        })
        .unwrap();

    let mut loader = BuiltinProgram::new_loader(config.clone());

    // Stub syscalls
    // Note: unstubbed_runtime is "v1", so syscalls are only registered for version < V3,
    //       i.e. unstubbed_runtime.get_function_registry(sbpf_version) does NOT work.
    let syscall_reg = invoke_ctx
        .program_cache_for_tx_batch
        .environments
        .program_runtime_v1
        .get_function_registry();
    for (_key, (name, _func)) in syscall_reg.iter() {
        loader
            .register_function(std::str::from_utf8(name).unwrap(), SyscallStub::vm)
            .unwrap();
    }
    let loader = std::sync::Arc::new(loader);

    let function_registry = setup_internal_fn_registry(&vm_ctx, sbpf_version);
    /* TODO: ensure variable lifetime is valid */
    let text_bytes = vm_ctx.rodata().bytes();
    let mut executable =
        Executable::from_text_bytes(text_bytes, loader, sbpf_version, function_registry).unwrap();

    if executable.verify::<RequisiteVerifier>().is_err() {
        let effects = vm_generated::SyscallEffects::create(
            builder,
            &vm_generated::SyscallEffectsArgs {
                err_code: -2,
                ..Default::default()
            },
        );
        builder.finish_minimal(effects);
        return;
    }

    if !USE_INTERPRETER && executable.jit_compile().is_err() {
        let effects = vm_generated::SyscallEffects::create(
            builder,
            &vm_generated::SyscallEffectsArgs {
                err_code: -3,
                ..Default::default()
            },
        );
        builder.finish_minimal(effects);
        return;
    }

    // Setup TestContextObject
    let mut context_obj = TestContextObject::new(instr_ctx.cu_avail);

    // setup memory
    let heap_max = (vm_ctx.heap_max() as usize).min(crate::utils::vm::HEAP_MAX);
    let syscall_inv = syscall_context.syscall_invocation();

    let mut mempool = VmMemoryPool::new();
    let rodata = AlignedMemory::<HOST_ALIGN>::from(text_bytes);
    let mut stack = mempool.get_stack(STACK_SIZE);
    let mut heap = AlignedMemory::<HOST_ALIGN>::from(&vec![0; heap_max]);

    let rodata_stack_heap = vec![
        MemoryRegion::new_readonly(rodata.as_slice(), ebpf::MM_RODATA_START),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ];
    let regions = rodata_stack_heap
        .into_iter()
        .chain(input_memory_regions)
        .collect();

    /* The VM ranges for the constructed memory regions are well-formed,
    so this call can't fail. */
    let memory_mapping = MemoryMapping::new_with_access_violation_handler(
        regions,
        &config,
        sbpf_version,
        invoke_ctx
            .transaction_context
            .access_violation_handler(stricter_abi_and_runtime_constraints, direct_mapping),
    )
    .expect("Memory mapping construction should not fail");

    let mut vm = EbpfVm::new(
        executable.get_loader().clone(),
        executable.get_sbpf_version(),
        &mut context_obj,
        memory_mapping,
        STACK_SIZE,
    );

    // Setup registers.
    // r1, r10, r11 are initialized by EbpfVm::new (r10) or EbpfVm::execute_program (r11)
    // r1 is initialized in Agave at ebpf::MM_INPUT_START.
    // Modifying them will most like break execution.
    // In syscalls we allow override them (especially r1) because that simulates the fact
    // that a program partially executed before reaching the syscall.
    // Here we want to test what happens when the program starts from the beginning.
    vm.registers[0] = vm_ctx.r0();
    vm.registers[1] = ebpf::MM_INPUT_START;
    vm.registers[2] = vm_ctx.r2();
    vm.registers[3] = vm_ctx.r3();
    vm.registers[4] = vm_ctx.r4();
    vm.registers[5] = vm_ctx.r5();
    vm.registers[6] = vm_ctx.r6();
    vm.registers[7] = vm_ctx.r7();
    vm.registers[8] = vm_ctx.r8();
    vm.registers[9] = vm_ctx.r9();
    // vm.registers[10] = vm_ctx.r10; // do not override
    // vm.registers[11] = vm_ctx.r11; // do not override

    mem_regions_flatbuffers::copy_memory_prefix(
        heap.as_slice_mut(),
        &syscall_inv.heap_prefix().bytes(),
    );
    mem_regions_flatbuffers::copy_memory_prefix(
        stack.as_slice_mut(),
        &syscall_inv.stack_prefix().bytes(),
    );

    let (_, result) = vm.execute_program(
        &executable,
        USE_INTERPRETER, /* use JIT for fuzzing, interpreter for debugging */
    );

    // When a program fails, the register in trace_log are not properly
    // captured (they represent the state at the end of the previous ix).
    // For simplicity, we ignore them.
    let out_registers = match result {
        StableResult::Err(_) => &[0; 12],
        StableResult::Ok(_) => vm
            .context_object_pointer
            .trace_log
            .last()
            .unwrap_or(&[0; 12]),
    };

    if ENABLE_TRACE_DUMP {
        eprintln!("Tracing: {:x?}", vm.context_object_pointer.trace_log);
    }

    /* We do not compare VM state on CU errors since CU consumption is
    not precisely defined when VM faults. */
    if matches!(
        result,
        StableResult::Err(EbpfError::ExceededMaxInstructions)
    ) {
        let effects = vm_generated::SyscallEffects::create(
            builder,
            &vm_generated::SyscallEffectsArgs {
                err_code: err_map_flatbuffers::ebpf_err_to_num(&EbpfError::ExceededMaxInstructions)
                    as i8,
                ..Default::default()
            },
        );
        builder.finish_minimal(effects);
        return;
    }

    let heap_output = builder.create_vector(heap.as_slice());
    let stack_output = builder.create_vector_from_iter(vec_rtrim_zeros(stack.as_slice()).iter());
    let rodata_output = builder.create_vector(rodata.as_slice());
    let input_data_regions_vector =
        mem_regions_flatbuffers::extract_input_data_regions(&vm.memory_mapping, builder);
    let input_data_regions_output = builder.create_vector(input_data_regions_vector.as_slice());
    let effects = vm_generated::SyscallEffects::create(
        builder,
        &vm_generated::SyscallEffectsArgs {
            err_code: match result {
                StableResult::Ok(_) => 0,
                StableResult::Err(ref ebpf_err) => {
                    err_map_flatbuffers::ebpf_err_to_num(ebpf_err) as i8
                }
            },
            r0: out_registers[0],
            r1: out_registers[1],
            r2: out_registers[2],
            r3: out_registers[3],
            r4: out_registers[4],
            r5: out_registers[5],
            r6: out_registers[6],
            r7: out_registers[7],
            r8: out_registers[8],
            r9: out_registers[9],
            r10: out_registers[10],
            cu_avail: vm.context_object_pointer.get_remaining(),
            frame_count: vm.call_depth,
            heap: Some(heap_output),
            stack: Some(stack_output),
            rodata: Some(rodata_output),
            input_data_regions: Some(input_data_regions_output),
            pc: match vm.context_object_pointer.trace_log.last() {
                Some(regs) => regs[11],
                None => vm.registers[11],
            },
            ..Default::default()
        },
    );
    builder.finish_minimal(effects);
}
