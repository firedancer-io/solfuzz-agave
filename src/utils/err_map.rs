use solana_syscalls::SyscallError;
use protosol::protos::ErrKind;
use solana_poseidon::PoseidonSyscallError;
use solana_program_runtime::{
    cpi::CpiError, invoke_context::InvokeContext, memory::MemoryTranslationError, stable_log,
};
use solana_sbpf::{
    elf::ElfError,
    error::{EbpfError, StableResult},
};

use solana_instruction::error::InstructionError;
use solana_pubkey::Pubkey;

// Important!
// The error mapping in this file should be kept aligned with Firedancer.
// Specifically:
// - err num is generally Agave's enum as u8 + 1, and -num in Firedancer
// - err str in Agave may have parameters, in Firedancer these are often truncated.
//   When an err str is truncated in Firedancer, it should be explicit in this mapping,
//   otherwise error.to_string() is the expected value.

pub fn elf_err_to_num(error: &ElfError) -> u8 {
    match error {
        ElfError::FailedToParse(_) => 1,
        ElfError::EntrypointOutOfBounds => 2,
        ElfError::InvalidEntrypoint => 3,
        ElfError::FailedToGetSection(_) => 4,
        ElfError::UnresolvedSymbol(_, _, _) => 5,
        ElfError::SectionNotFound(_) => 6,
        ElfError::RelativeJumpOutOfBounds(_) => 7,
        ElfError::SymbolHashCollision(_) => 8,
        ElfError::WrongEndianess => 9,
        ElfError::WrongAbi => 10,
        ElfError::WrongMachine => 11,
        ElfError::WrongClass => 12,
        ElfError::NotOneTextSection => 13,
        ElfError::WritableSectionNotSupported(_) => 14,
        ElfError::AddressOutsideLoadableSection(_) => 15,
        ElfError::InvalidVirtualAddress(_) => 16,
        ElfError::UnknownRelocation(_) => 17,
        ElfError::FailedToReadRelocationInfo => 18,
        ElfError::WrongType => 19,
        ElfError::UnknownSymbol(_) => 20,
        ElfError::ValueOutOfBounds => 21,
        ElfError::UnsupportedSBPFVersion => 22,
        ElfError::InvalidProgramHeader => 23,
    }
}

pub fn instr_err_to_num(error: &InstructionError) -> i32 {
    let serialized_err = bincode::serialize(error).unwrap();
    i32::from_le_bytes((&serialized_err[0..4]).try_into().unwrap()).saturating_add(1)
}

pub fn syscall_err_to_num(error: &SyscallError) -> i32 {
    let err: i32 = match error {
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
    err.saturating_add(1)
}

pub fn ebpf_err_to_num(error: &EbpfError) -> i32 {
    let err: i32 = match error {
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
        EbpfError::InvalidMemoryRegion(_) => 11,
        EbpfError::AccessViolation(_, _, _, _) => 12,
        EbpfError::StackAccessViolation(_, _, _, _) => 13,
        EbpfError::InvalidInstruction => 14,
        EbpfError::UnsupportedInstruction => 15,
        EbpfError::ExhaustedTextSegment(_) => 16,
        EbpfError::LibcInvocationFailed(_, _, _) => 17,
        EbpfError::VerifierError(_) => 18,
        EbpfError::SyscallError(_) => -10, // this should never be used as dyn errors are explicitly downcasted
    };
    err.saturating_add(1)
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
                    stable_log::program_failure(&logger, program_id, &instruction_err.to_string());
                    (instr_err_to_num(instruction_err), ErrKind::Instruction)
                } else if let Some(syscall_error) = syscall_error.downcast_ref::<SyscallError>() {
                    stable_log::program_failure(&logger, program_id, &syscall_error.to_string());
                    (syscall_err_to_num(syscall_error), ErrKind::Syscall)
                } else if let Some(memory_error) =
                    syscall_error.downcast_ref::<MemoryTranslationError>()
                {
                    let syscall_error: SyscallError = (memory_error.clone()).into();
                    stable_log::program_failure(&logger, program_id, &syscall_error.to_string());
                    (syscall_err_to_num(&syscall_error), ErrKind::Syscall)
                } else if let Some(cpi_error) = syscall_error.downcast_ref::<CpiError>() {
                    let syscall_error: SyscallError = (cpi_error.clone()).into();
                    stable_log::program_failure(&logger, program_id, &syscall_error.to_string());
                    (syscall_err_to_num(&syscall_error), ErrKind::Syscall)
                } else if let Some(ebpf_error) = syscall_error.downcast_ref::<EbpfError>() {
                    stable_log::program_failure(&logger, program_id, &ebpf_error.to_string());
                    (ebpf_err_to_num(ebpf_error), ErrKind::Ebpf)
                } else if syscall_error
                    .downcast_ref::<PoseidonSyscallError>()
                    .is_some()
                {
                    // Don't bother logging PoseidonSyscallError, it's not logged in Agave
                    (-1, ErrKind::Syscall)
                } else {
                    // This should never happen, so we return -1 to highlight an unknown error
                    stable_log::program_failure(&logger, program_id, &err.to_string());
                    (-1, ErrKind::Unspecified)
                }
            } else {
                stable_log::program_failure(&logger, program_id, &err.to_string());
                (ebpf_err_to_num(err), ErrKind::Ebpf)
            };
            (err_no as i64, err_kind, 0)
        }
    }
}
