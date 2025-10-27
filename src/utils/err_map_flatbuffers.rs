use agave_syscalls::SyscallError;
use solana_poseidon::PoseidonSyscallError;
use solana_program_runtime::{invoke_context::InvokeContext, stable_log};
use solana_sbpf::{
    elf::ElfError,
    error::{EbpfError, StableResult},
};

use crate::vm_generated;
use solana_instruction::error::InstructionError;
use solana_pubkey::Pubkey;
use solana_transaction_error::TransactionError;

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

pub fn txn_err_to_num(error: &TransactionError) -> u8 {
    match error {
        TransactionError::AccountInUse => 1,
        TransactionError::AccountLoadedTwice => 2,
        TransactionError::AccountNotFound => 3,
        TransactionError::ProgramAccountNotFound => 4,
        TransactionError::InsufficientFundsForFee => 5,
        TransactionError::InvalidAccountForFee => 6,
        TransactionError::AlreadyProcessed => 7,
        TransactionError::BlockhashNotFound => 8,
        TransactionError::InstructionError(_, _) => 9,
        TransactionError::CallChainTooDeep => 10,
        TransactionError::MissingSignatureForFee => 11,
        TransactionError::InvalidAccountIndex => 12,
        TransactionError::SignatureFailure => 13,
        TransactionError::InvalidProgramForExecution => 14,
        TransactionError::SanitizeFailure => 15,
        TransactionError::ClusterMaintenance => 16,
        TransactionError::AccountBorrowOutstanding => 17,
        TransactionError::WouldExceedMaxBlockCostLimit => 18,
        TransactionError::UnsupportedVersion => 19,
        TransactionError::InvalidWritableAccount => 20,
        TransactionError::WouldExceedMaxAccountCostLimit => 21,
        TransactionError::WouldExceedAccountDataBlockLimit => 22,
        TransactionError::TooManyAccountLocks => 23,
        TransactionError::AddressLookupTableNotFound => 24,
        TransactionError::InvalidAddressLookupTableOwner => 25,
        TransactionError::InvalidAddressLookupTableData => 26,
        TransactionError::InvalidAddressLookupTableIndex => 27,
        TransactionError::InvalidRentPayingAccount => 28,
        TransactionError::WouldExceedMaxVoteCostLimit => 29,
        TransactionError::WouldExceedAccountDataTotalLimit => 30,
        TransactionError::DuplicateInstruction(_) => 31,
        TransactionError::InsufficientFundsForRent { .. } => 32,
        TransactionError::MaxLoadedAccountsDataSizeExceeded => 33,
        TransactionError::InvalidLoadedAccountsDataSizeLimit => 34,
        TransactionError::ResanitizationNeeded => 35,
        TransactionError::ProgramExecutionTemporarilyRestricted { .. } => 36,
        TransactionError::UnbalancedTransaction => 37,
        TransactionError::ProgramCacheHitMaxLimit => 38,
        TransactionError::CommitCancelled => 39,
    }
}

pub fn instr_err_to_num(error: &InstructionError) -> u8 {
    match error {
        InstructionError::GenericError => 1,
        InstructionError::InvalidArgument => 2,
        InstructionError::InvalidInstructionData => 3,
        InstructionError::InvalidAccountData => 4,
        InstructionError::AccountDataTooSmall => 5,
        InstructionError::InsufficientFunds => 6,
        InstructionError::IncorrectProgramId => 7,
        InstructionError::MissingRequiredSignature => 8,
        InstructionError::AccountAlreadyInitialized => 9,
        InstructionError::UninitializedAccount => 10,
        InstructionError::UnbalancedInstruction => 11,
        InstructionError::ModifiedProgramId => 12,
        InstructionError::ExternalAccountLamportSpend => 13,
        InstructionError::ExternalAccountDataModified => 14,
        InstructionError::ReadonlyLamportChange => 15,
        InstructionError::ReadonlyDataModified => 16,
        InstructionError::DuplicateAccountIndex => 17,
        InstructionError::ExecutableModified => 18,
        InstructionError::RentEpochModified => 19,
        InstructionError::NotEnoughAccountKeys => 20,
        InstructionError::AccountDataSizeChanged => 21,
        InstructionError::AccountNotExecutable => 22,
        InstructionError::AccountBorrowFailed => 23,
        InstructionError::AccountBorrowOutstanding => 24,
        InstructionError::DuplicateAccountOutOfSync => 25,
        InstructionError::Custom(_) => 26,
        InstructionError::InvalidError => 27,
        InstructionError::ExecutableDataModified => 28,
        InstructionError::ExecutableLamportChange => 29,
        InstructionError::ExecutableAccountNotRentExempt => 30,
        InstructionError::UnsupportedProgramId => 31,
        InstructionError::CallDepth => 32,
        InstructionError::MissingAccount => 33,
        InstructionError::ReentrancyNotAllowed => 34,
        InstructionError::MaxSeedLengthExceeded => 35,
        InstructionError::InvalidSeeds => 36,
        InstructionError::InvalidRealloc => 37,
        InstructionError::ComputationalBudgetExceeded => 38,
        InstructionError::PrivilegeEscalation => 39,
        InstructionError::ProgramEnvironmentSetupFailure => 40,
        InstructionError::ProgramFailedToComplete => 41,
        InstructionError::ProgramFailedToCompile => 42,
        InstructionError::Immutable => 43,
        InstructionError::IncorrectAuthority => 44,
        InstructionError::BorshIoError => 45,
        InstructionError::AccountNotRentExempt => 46,
        InstructionError::InvalidAccountOwner => 47,
        InstructionError::ArithmeticOverflow => 48,
        InstructionError::UnsupportedSysvar => 49,
        InstructionError::IllegalOwner => 50,
        InstructionError::MaxAccountsDataAllocationsExceeded => 51,
        InstructionError::MaxAccountsExceeded => 52,
        InstructionError::MaxInstructionTraceLengthExceeded => 53,
        InstructionError::BuiltinProgramsMustConsumeComputeUnits => 54,
    }
}

pub fn syscall_err_to_num(error: &SyscallError) -> u8 {
    match error {
        SyscallError::InvalidString(_, _) => 1,
        SyscallError::Abort => 2,
        SyscallError::Panic(_, _, _) => 3,
        SyscallError::InvokeContextBorrowFailed => 4,
        SyscallError::MalformedSignerSeed(_, _) => 5,
        SyscallError::BadSeeds(_) => 6,
        SyscallError::ProgramNotSupported(_) => 7,
        SyscallError::UnalignedPointer => 8,
        SyscallError::TooManySigners => 9,
        SyscallError::InstructionTooLarge(_, _) => 10,
        SyscallError::TooManyAccounts => 11,
        SyscallError::CopyOverlapping => 12,
        SyscallError::ReturnDataTooLarge(_, _) => 13,
        SyscallError::TooManySlices => 14,
        SyscallError::InvalidLength => 15,
        SyscallError::MaxInstructionDataLenExceeded {
            data_len: _,
            max_data_len: _,
        } => 16,
        SyscallError::MaxInstructionAccountsExceeded {
            num_accounts: _,
            max_accounts: _,
        } => 17,
        SyscallError::MaxInstructionAccountInfosExceeded {
            num_account_infos: _,
            max_account_infos: _,
        } => 18,
        SyscallError::InvalidAttribute => 19,
        SyscallError::InvalidPointer => 20,
        SyscallError::ArithmeticOverflow => 21,
    }
}

pub fn ebpf_err_to_num(error: &EbpfError) -> u8 {
    match error {
        EbpfError::ElfError(_) => 1,
        EbpfError::FunctionAlreadyRegistered(_) => 2,
        EbpfError::CallDepthExceeded => 3,
        EbpfError::ExitRootCallFrame => 4,
        EbpfError::DivideByZero => 5,
        EbpfError::DivideOverflow => 6,
        EbpfError::ExecutionOverrun => 7,
        EbpfError::CallOutsideTextSegment => 8,
        EbpfError::ExceededMaxInstructions => 9,
        EbpfError::JitNotCompiled => 10,
        EbpfError::InvalidMemoryRegion(_) => 12,
        EbpfError::AccessViolation(_, _, _, _) => 13,
        EbpfError::StackAccessViolation(_, _, _, _) => 14,
        EbpfError::InvalidInstruction => 15,
        EbpfError::UnsupportedInstruction => 16,
        EbpfError::ExhaustedTextSegment(_) => 17,
        EbpfError::LibcInvocationFailed(_, _, _) => 18,
        EbpfError::VerifierError(_) => 19,
        EbpfError::SyscallError(_) => 0, // this should never be used as dyn errors are explicitly downcasted
    }
}

pub fn unpack_stable_result(
    program_result: StableResult<u64, EbpfError>,
    invoke_context: &InvokeContext,
    program_id: &Pubkey,
) -> (u8, vm_generated::ErrKind, u64) {
    match program_result {
        StableResult::Ok(n) => (0, vm_generated::ErrKind::UNSPECIFIED, n),
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
                    (
                        instr_err_to_num(instruction_err),
                        vm_generated::ErrKind::INSTRUCTION,
                    )
                } else if let Some(syscall_error) = syscall_error.downcast_ref::<SyscallError>() {
                    stable_log::program_failure(&logger, program_id, &syscall_error.to_string());
                    (
                        syscall_err_to_num(syscall_error),
                        vm_generated::ErrKind::SYSCALL,
                    )
                } else if let Some(ebpf_error) = syscall_error.downcast_ref::<EbpfError>() {
                    stable_log::program_failure(&logger, program_id, &ebpf_error.to_string());
                    (ebpf_err_to_num(ebpf_error), vm_generated::ErrKind::EBPF)
                } else if syscall_error
                    .downcast_ref::<PoseidonSyscallError>()
                    .is_some()
                {
                    // Don't bother logging PoseidonSyscallError, it's not logged in Agave
                    (0xFF, vm_generated::ErrKind::SYSCALL)
                } else {
                    // This should never happen, so we return -1 to highlight an unknown error
                    stable_log::program_failure(&logger, program_id, &err.to_string());
                    (0xFF, vm_generated::ErrKind::UNSPECIFIED)
                }
            } else {
                stable_log::program_failure(&logger, program_id, &err.to_string());
                (ebpf_err_to_num(err), vm_generated::ErrKind::EBPF)
            };
            (err_no, err_kind, 0)
        }
    }
}
