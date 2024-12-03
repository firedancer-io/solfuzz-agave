/* DEPRECATED, use utils/err_map.rs instead. Saving this for vm_interp.rs, which will
need more substantial changes to accomodate the newer err_map.rs */
use solana_program_runtime::solana_rbpf::error::EbpfError;
use solana_program_runtime::solana_rbpf::verifier::VerifierError;
const TRUNCATE_ERROR_WORDS: usize = 7;

pub fn get_fd_vm_err_code(ebpf_err: &EbpfError) -> i32 {
    match ebpf_err {
        EbpfError::VerifierError(err) => verifer_error_match(err),
        EbpfError::SyscallError(err) => syscall_error_match(err.as_ref()),

        /* VM Execution Errors */
        EbpfError::CallOutsideTextSegment => 8, /* FD_VM_ERR_SIGTEXT  */
        EbpfError::ExecutionOverrun => 8,       /* FD_VM_ERR_SIGTEXT */
        EbpfError::UnsupportedInstruction => 12, /* FD_VM_ERR_SIGILL */
        EbpfError::CallDepthExceeded => 11,     /* FD_VM_ERR_SIGSTACK */
        EbpfError::InvalidInstruction => 12,    /* FD_VM_ERR_SIGILL */
        EbpfError::AccessViolation(_, _, _, _) => 13, /* FD_VM_ERR_SIGSEGV */
        EbpfError::StackAccessViolation(_, _, _, _) => 13, /* FD_VM_ERR_SIGSEGV */
        /* FD_VM_ERR_SIGBUS (14) and FD_VM_ERR_SIGRDONLY (15) not used */
        EbpfError::ExceededMaxInstructions => 16, /* FD_VM_ERR_SIGCOST*/
        EbpfError::DivideByZero => 18,            /* FD_VM_ERR_SIGFPE */
        /* EbpfError::DivideOverflow isn't possible in SBPFv1 bytecode,
        so we don't have a mapping.  */
        err => {
            eprintln!("unknown error: {:?}", err);
            -1
        }
    }
}

fn truncate_error_str(s: String) -> String {
    s.split_whitespace()
        .take(TRUNCATE_ERROR_WORDS)
        .collect::<Vec<_>>()
        .join(" ")
}

fn verifer_error_match(ver_err: &VerifierError) -> i32 {
    // https://github.com/firedancer-io/firedancer/blob/f878e448e5511c3600e2dd6360a4f06ce793af6f/src/flamenco/vm/fd_vm_base.h#L67
    match ver_err {
        VerifierError::NoProgram => 6,
        VerifierError::DivisionByZero(_) => 18,
        VerifierError::UnknownOpCode(_, _) => 25,
        VerifierError::InvalidSourceRegister(_) => 26,
        VerifierError::InvalidDestinationRegister(_) => 27,
        VerifierError::CannotWriteR10(_) => 27, // FD treats this the same as InvalidDestinationRegister
        VerifierError::InfiniteLoop(_) => 28,   // Not checked here (nor in FD)
        VerifierError::JumpOutOfCode(_, _) => 29,
        VerifierError::JumpToMiddleOfLDDW(_, _) => 30,
        VerifierError::UnsupportedLEBEArgument(_) => 31,
        VerifierError::LDDWCannotBeLast => 32,
        VerifierError::IncompleteLDDW(_) => 33,
        VerifierError::InvalidRegister(_) => 35,
        VerifierError::ShiftWithOverflow(_, _, _) => 37,
        VerifierError::ProgramLengthNotMultiple => 38,
        _ => -1,
    }
}

fn syscall_error_match(sys_err: &dyn std::error::Error) -> i32 {
    // Error matching.
    // Errors are `EbpfError`` and in particular we need to match EbpfError::Syscall == Box<dyn Error>.
    // In turn, the dynamic error can have multiple types, for example InstructionError or SyscallError.
    // And... we need to match them against Firedancer errors.
    // To make things as simple as possible, we match explicit error messages to Firedancer error numbers.
    // Unfortunately even this is not that simple, because most error messages contain dynamic fields.
    // So, the current solutio truncates the error message to TRUNCATE_ERROR_WORDS words, where the constant
    // is chosen to be large enough to distinguish errors, and small enough to avoid variable strings.
    match truncate_error_str(sys_err.to_string()).as_str() {
        // InstructionError
        // https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/program/src/instruction.rs#L33
        "Computational budget exceeded" => 16,
        // SyscallError
        // https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/programs/bpf_loader/src/syscalls/mod.rs#L77
        "Hashing too many sequences" => 1,
        "InvalidLength" => 1,
        "InvalidAttribute" => 1,
        // ??
        "Access violation in program section at address" => 13,
        "Access violation in stack section at address" => 13,
        "Access violation in heap section at address" => 13,
        "Access violation in unknown section at address" => 13,
        // https://github.com/solana-labs/solana/blob/v1.18.12/sdk/program/src/poseidon.rs#L13
        "Invalid parameters." => 1,
        "Invalid endianness." => 1,
        // EbpfError
        // https://github.com/solana-labs/rbpf/blob/main/src/error.rs#L17
        _ => -1,
    }
}
