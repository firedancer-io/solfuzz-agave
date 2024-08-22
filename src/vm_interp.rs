use crate::{
    proto::{SyscallContext, SyscallEffects, VmContext},
    utils::{
        pchash_inverse,
        vm::{err_map, mem_regions, HEAP_MAX, STACK_SIZE},
    },
    InstrContext,
};
use bincode::Error;
use prost::Message;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_program_runtime::solana_rbpf::{
    declare_builtin_function, ebpf,
    elf::Executable,
    error::{EbpfError, StableResult},
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{Config, ContextObject, EbpfVm, TestContextObject},
};
use std::{borrow::Borrow, ffi::c_int};

declare_builtin_function!(
    SyscallStub,
    fn rust(
        _invoke_context: &mut TestContextObject,
        _hash_addr: u64,
        _recovery_id_val: u64,
        _signature_addr: u64,
        _result_addr: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        // TODO: deduct CUs?
        Ok(0)
    }
);

/* Set to true to make debugging easier

WARNING: CU validation works differently in the
interpreter vs. JIT. You may get CU mismatches you
otherwise wouldn't see when fuzzing against the JIT.

FD targets conformance with the JIT, not interprerter. */
const USE_INTERPRETER: bool = false;

/* Set to true to dump registers[0..12] of every instruction
execution (dumped after execution). Please leave disabled
for fuzzing. */
const ENABLE_TRACE_DUMP: bool = false;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_interp_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if USE_INTERPRETER {
        eprintln!("WARNING: Using interpreter instead of the JIT. This is not the fuzz default.");
    }
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

// We are actually executing the JIT-compiled program here
fn execute_vm_interp(syscall_context: SyscallContext) -> Option<SyscallEffects> {
    let instr_ctx: InstrContext = syscall_context.instr_ctx?.try_into().ok()?;
    let feature_set = instr_ctx.feature_set;

    // Load default syscalls, to be stubbed later
    let unstubbed_runtime = create_program_runtime_environment_v1(
        &feature_set,
        &ComputeBudget::default(),
        false,
        true, /* capture register state to obtain pc on success */
    )
    .unwrap();

    // stub syscalls
    let syscall_reg = unstubbed_runtime.get_function_registry();
    let mut stubbed_syscall_reg = FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();

    for (key, (name, _)) in syscall_reg.iter() {
        stubbed_syscall_reg
            .register_function(key, name, SyscallStub::vm)
            .unwrap();
    }
    let program_runtime_environment_v1 =
        BuiltinProgram::new_loader(*unstubbed_runtime.get_config(), stubbed_syscall_reg);

    let sbpf_version: SBPFVersion = SBPFVersion::V1;
    let loader = std::sync::Arc::new(program_runtime_environment_v1);

    // Setup TestContextObject
    let mut context_obj = TestContextObject::new(instr_ctx.cu_avail);

    // setup memory
    let vm_ctx = syscall_context.vm_ctx.unwrap();
    let function_registry = setup_internal_fn_registry(&vm_ctx);

    let syscall_inv = syscall_context.syscall_invocation.unwrap();

    let rodata = &vm_ctx.rodata;
    let mut stack = syscall_inv.stack_prefix;
    stack.resize(STACK_SIZE, 0);
    let mut heap = syscall_inv.heap_prefix;
    heap.resize(HEAP_MAX, 0);

    let mut regions = vec![
        MemoryRegion::new_readonly(rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
    ];

    let mut input_data_regions = vm_ctx.input_data_regions.clone();
    mem_regions::setup_input_regions(&mut regions, &mut input_data_regions);
    let config = &Config {
        aligned_memory_mapping: true,
        enable_sbpf_v2: false,
        ..Config::default()
    };

    let memory_mapping = match MemoryMapping::new(regions, config, &sbpf_version) {
        Ok(mapping) => mapping,
        Err(_) => return None,
    };

    let mut vm = EbpfVm::new(
        loader.clone(),
        &sbpf_version,
        &mut context_obj,
        memory_mapping,
        STACK_SIZE,
    );

    // setup registers
    vm.registers[0] = vm_ctx.r0;
    vm.registers[1] = vm_ctx.r1; // set in vm.execute_program
    vm.registers[2] = vm_ctx.r2;
    vm.registers[3] = vm_ctx.r3;
    vm.registers[4] = vm_ctx.r4;
    vm.registers[5] = vm_ctx.r5;
    vm.registers[6] = vm_ctx.r6;
    vm.registers[7] = vm_ctx.r7;
    vm.registers[8] = vm_ctx.r8;
    vm.registers[9] = vm_ctx.r9;
    vm.registers[10] = vm_ctx.r10; // set in vm.execute_program
    vm.registers[11] = vm_ctx.r11; // set in vm.execute_program

    let mut executable = Executable::from_text_bytes(
        &vm_ctx.rodata,
        loader,
        sbpf_version.clone(),
        function_registry,
    )
    .unwrap();

    if executable.verify::<RequisiteVerifier>().is_err() {
        return Some(SyscallEffects {
            error: -1,
            ..Default::default()
        });
    }

    if executable.jit_compile().is_err() {
        return Some(SyscallEffects {
            error: -1,
            ..Default::default()
        });
    }

    let (_, result) = vm.execute_program(
        &executable,
        USE_INTERPRETER, /* use JIT for fuzzing, interpreter for debugging */
    );

    if ENABLE_TRACE_DUMP {
        eprintln!("Tracing: {:x?}", vm.context_object_pointer.trace_log);
    }

    let result = match result {
        StableResult::Err(err) => StableResult::Err(process_result(&mut vm, &executable, err)),
        StableResult::Ok(n) => StableResult::Ok(n),
    };

    if let StableResult::Err(err) = result.borrow() {
        if let EbpfError::ExceededMaxInstructions = err {
            /* CU error is difficult to properly compare as there may have been
            valid writes to the memory regions prior to capturing the error. And
            the pc might be well past (by an arbitrary amount) the instruction
            where the CU error occurred. */
            return Some(SyscallEffects {
                error: err_map::get_fd_vm_err_code(err).into(),
                cu_avail: 0,
                frame_count: vm.call_depth,
                ..Default::default()
            });
        }
    }

    Some(SyscallEffects {
        error: match result {
            StableResult::Ok(_) => 0,
            StableResult::Err(ref ebpf_err) => err_map::get_fd_vm_err_code(ebpf_err).into(),
        },
        r0: match result {
            StableResult::Ok(n) => n,
            StableResult::Err(_) => 0,
        },
        cu_avail: vm.context_object_pointer.get_remaining(),
        frame_count: vm.call_depth,
        heap,
        stack,
        rodata: rodata.to_vec(),
        input_data_regions: mem_regions::extract_input_data_regions(&vm.memory_mapping),
        log: vec![],
        pc: match result {
            StableResult::Ok(_) => match vm.context_object_pointer.trace_log.last() {
                Some(regs) => regs[11],
                None => vm.registers[11],
            },
            StableResult::Err(_) => vm.registers[11],
        },
        ..Default::default() // FIXME: implement rodata
    })
}

/* This sets up a function registry based on a Firedancer-loaded SBPF program.
The key difference is call immediates are hashed based on their target pc,
not the function symbol. Firedancer maintains a bit vector of all valid call
destinations[1], which the interpreter uses during the CALL_IMM instruction.

To mimic that behavior here, we iterate through the valid call destinations
in vm_ctx.call_whitelist, and register the pc hash as an entry in the registry.

This effectively behaves the same as the FD bit vector, but with some technical
differences that may cause issues. Most notably, FunctionRegistry operates as
a hashmap, while FD's bit vector is a simple array. Out of bounds queries are
non-issue here, but require explicit handling in FD. This causes a slight
difference in error checks in CALL_IMM, which we handle in process_result.

[1](https://github.com/firedancer-io/firedancer/blob/93cea434dfe2f728f2ab4746590972644c06b863/src/ballet/sbpf/fd_sbpf_loader.h#L27). */
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
                    ebpf::hash_symbol_name(&u64::to_le_bytes(pc as u64)),
                    b"fn",
                    pc,
                );
            }
        }
    }

    fn_reg
}

/* Look through errors, and map to something else if necessary */
fn process_result<C: ContextObject>(
    vm: &mut EbpfVm<C>,
    executable: &Executable<C>,
    err: EbpfError,
) -> EbpfError {
    match err {
        EbpfError::UnsupportedInstruction => {
            /* CALL_IMM throws UnsupportedInstruction iff the immediate
            is not in executable's Function Registry. We want
            to consider the case that the hash inverse is a PC(*) that is
            OOB, since Firedancer reports the equivalent to
            EbpfError::CallOutsideTextSegment.

            (*) NOTE: this assumes a text section loaded by the FD sbpf loader,
            which hashes the PC of the target function into the instruction immediate.
            The interpreter fuzzer uses this. */

            let pc = vm.registers[11];
            let insn = ebpf::get_insn_unchecked(executable.get_text_bytes().1, pc as usize);
            if insn.opc == ebpf::CALL_IMM {
                let pchash = insn.imm as u32;
                if pchash_inverse(pchash)
                    > (executable.get_text_bytes().1.len() / ebpf::INSN_SIZE) as u32
                {
                    // need to simulate pushing a stack frame
                    vm.call_depth += 1;
                    EbpfError::CallOutsideTextSegment
                } else {
                    EbpfError::UnsupportedInstruction
                }
            } else {
                EbpfError::UnsupportedInstruction
            }
        }
        _ => err,
    }
}
