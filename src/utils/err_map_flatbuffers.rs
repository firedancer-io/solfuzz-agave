use solana_sbpf::elf::ElfError;

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
