use crate::proto::ErrKind;
use solana_bpf_loader_program::syscalls::SyscallError;
use solana_poseidon::PoseidonSyscallError;
use solana_program_runtime::{
    invoke_context::InvokeContext,
    solana_rbpf::error::{EbpfError, StableResult},
    stable_log,
};

use solana_sdk::{instruction::InstructionError, pubkey::Pubkey};

// Important!
// The error mapping in this file should be kept aligned with Firedancer.
// Specifically:
// - err num is generally Agave's enum as u8 + 1, and -num in Firedancer
// - err str in Agave may have parameters, in Firedancer these are often truncated.
//   When an err str is truncated in Firedancer, it should be explicit in this mapping,
//   otherwise error.to_string() is the expected value.

pub fn instr_err_to_num(error: &InstructionError) -> i32 {
    let serialized_err = bincode::serialize(error).unwrap();
    i32::from_le_bytes((&serialized_err[0..4]).try_into().unwrap()) + 1
}

pub fn instr_err_to_str(error: &InstructionError) -> String {
    match error {
        // Simplified to: Failed to serialize or deserialize account data
        InstructionError::BorshIoError(_) => {
            "Failed to serialize or deserialize account data".to_string()
        }
        _ => error.to_string(),
    }
}

pub fn syscall_err_to_num(error: &SyscallError) -> i32 {
    let err = match error {
        SyscallError::InvalidString(_, _) => 0,
        SyscallError::Abort => 1,
        SyscallError::Panic(_, _, _) => 2,
        SyscallError::InvokeContextBorrowFailed => 3,
        SyscallError::MalformedSignerSeed(_, _) => 4,
        SyscallError::BadSeeds(_) => 5,
        SyscallError::ProgramNotSupported(_) => 6,
        SyscallError::UnalignedPointer => 7,
        SyscallError::TooManySigners => 8,
        SyscallError::InstructionTooLarge(_, _) => 9,
        SyscallError::TooManyAccounts => 10,
        SyscallError::CopyOverlapping => 11,
        SyscallError::ReturnDataTooLarge(_, _) => 12,
        SyscallError::TooManySlices => 13,
        SyscallError::InvalidLength => 14,
        SyscallError::MaxInstructionDataLenExceeded {
            data_len: _,
            max_data_len: _,
        } => 15,
        SyscallError::MaxInstructionAccountsExceeded {
            num_accounts: _,
            max_accounts: _,
        } => 16,
        SyscallError::MaxInstructionAccountInfosExceeded {
            num_account_infos: _,
            max_account_infos: _,
        } => 17,
        SyscallError::InvalidAttribute => 18,
        SyscallError::InvalidPointer => 19,
        SyscallError::ArithmeticOverflow => 20,
    };
    err + 1
}

pub fn syscall_err_to_str(error: &SyscallError) -> String {
    match error {
        // InvalidString prints rust std::str::Utf8Error, we simplify a bit
        SyscallError::InvalidString(_, _) => "invalid utf-8 sequence".to_string(),
        SyscallError::Panic(_, _, _) => "SBF program Panicked in...".to_string(),
        SyscallError::MalformedSignerSeed(_, _) => "Malformed signer seed".to_string(),
        SyscallError::BadSeeds(_) => {
            "Could not create program address with signer seeds".to_string()
        }
        SyscallError::ProgramNotSupported(_) => {
            "Program not supported by inner instructions".to_string()
        }
        SyscallError::InstructionTooLarge(_, _) => {
            "Instruction passed to inner instruction is too large".to_string()
        }
        SyscallError::ReturnDataTooLarge(_, _) => "Return data too large".to_string(),
        SyscallError::MaxInstructionDataLenExceeded {
            data_len: _,
            max_data_len: _,
        } => "Invoked an instruction with data that is too large".to_string(),
        SyscallError::MaxInstructionAccountsExceeded {
            num_accounts: _,
            max_accounts: _,
        } => "Invoked an instruction with too many accounts".to_string(),
        SyscallError::MaxInstructionAccountInfosExceeded {
            num_account_infos: _,
            max_account_infos: _,
        } => "Invoked an instruction with too many account info".to_string(),
        _ => error.to_string(),
    }
}

pub fn ebpf_err_to_num(error: &EbpfError) -> i32 {
    let err = match error {
        EbpfError::ElfError(_) => 0,
        EbpfError::FunctionAlreadyRegistered(_) => 1,
        EbpfError::CallDepthExceeded => 2,
        EbpfError::ExitRootCallFrame => 3,
        EbpfError::DivideByZero => 4,
        EbpfError::DivideOverflow => 5,
        EbpfError::ExecutionOverrun => 6,
        EbpfError::CallOutsideTextSegment => 7,
        EbpfError::ExceededMaxInstructions => 8,
        EbpfError::JitNotCompiled => 9,
        EbpfError::InvalidVirtualAddress(_) => 10,
        EbpfError::InvalidMemoryRegion(_) => 11,
        // Note: AccessViolation and StackAccessViolation are the same in Firedancer
        // so we return the same value
        EbpfError::AccessViolation(_, _, _, _) => 12,
        EbpfError::StackAccessViolation(_, _, _, _) => 12, // it was: 13
        EbpfError::InvalidInstruction => 14,
        EbpfError::UnsupportedInstruction => 15,
        EbpfError::ExhaustedTextSegment(_) => 16,
        EbpfError::LibcInvocationFailed(_, _, _) => 17,
        EbpfError::VerifierError(_) => 18,
        EbpfError::SyscallError(_) => -10, // this should never be used as dyn errors are explicitly downcasted
    };
    err + 1
}

pub fn ebpf_err_to_str(error: &EbpfError) -> String {
    match error {
        EbpfError::ElfError(_) => "ELF error".to_string(),
        EbpfError::FunctionAlreadyRegistered(_) => "function was already registered".to_string(),
        EbpfError::InvalidVirtualAddress(_) => "invalid virtual address".to_string(),
        EbpfError::InvalidMemoryRegion(_) => "Invalid memory region at index".to_string(),
        // Note: AccessViolation and StackAccessViolation are the same in Firedancer
        // so we return the same value
        EbpfError::AccessViolation(_, _, _, _) => "Access violation".to_string(),
        EbpfError::StackAccessViolation(_, _, _, _) => {
            // it was: "Access violation in stack frame".to_string()
            "Access violation".to_string()
        }
        EbpfError::ExhaustedTextSegment(_) => {
            "Compilation exhausted text segment at BPF instruction".to_string()
        }
        EbpfError::LibcInvocationFailed(_, _, _) => "Libc calling returned error code".to_string(),
        EbpfError::VerifierError(_) => "Verifier error".to_string(),
        _ => error.to_string(),
    }
}

pub fn unpack_stable_result(
    program_result: StableResult<u64, EbpfError>,
    invoke_context: &InvokeContext,
    program_id: &Pubkey,
) -> (i64, ErrKind, u64) {
    match program_result {
        StableResult::Ok(n) => (0, ErrKind::Unspecified, n),
        StableResult::Err(ref err) => {
            // Agave/rust propagates errors with additional data, and eventually BPF Loader
            // logs an error message that depends on the type of error and contains data:
            // https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/invoke_context.rs#L535-L549
            //
            // Firedancer has a different behavior, it immediately creates the log
            // when the syscall fails (to avoid propagating data).
            // Therefore, to match the results, we need to simulate the extra log.
            //
            // In the following code we parse error msg and error num in the same way
            // as Agave does (and logs with stable_log::program_failure()), i.e. by
            // distinguishing InstructionError, SyscallError or EbpfError.
            let logger = invoke_context.get_log_collector();
            let (err_no, err_kind) = if let EbpfError::SyscallError(syscall_error) = err {
                if let Some(instruction_err) = syscall_error.downcast_ref::<InstructionError>() {
                    stable_log::program_failure(
                        &logger,
                        program_id,
                        &instr_err_to_str(instruction_err),
                    );
                    (instr_err_to_num(instruction_err), ErrKind::Instruction)
                } else if let Some(syscall_error) = syscall_error.downcast_ref::<SyscallError>() {
                    stable_log::program_failure(
                        &logger,
                        program_id,
                        &syscall_err_to_str(syscall_error),
                    );
                    (syscall_err_to_num(syscall_error), ErrKind::Syscall)
                } else if let Some(syscall_error) = syscall_error.downcast_ref::<EbpfError>() {
                    stable_log::program_failure(
                        &logger,
                        program_id,
                        &ebpf_err_to_str(syscall_error),
                    );
                    (ebpf_err_to_num(syscall_error), ErrKind::Ebpf)
                } else if syscall_error
                    .downcast_ref::<PoseidonSyscallError>()
                    .is_some()
                {
                    // Don't bother logging PoseidonSyscallError, it's not logged in Agave
                    (-1, ErrKind::Syscall)
                } else {
                    // This should never happen, so we return -1 to highlight an unknown error
                    stable_log::program_failure(&logger, program_id, &ebpf_err_to_str(err));
                    (-1, ErrKind::Unspecified)
                }
            } else {
                stable_log::program_failure(&logger, program_id, &ebpf_err_to_str(err));
                (ebpf_err_to_num(err), ErrKind::Ebpf)
            };
            (err_no as i64, err_kind, 0)
        }
    }
}
