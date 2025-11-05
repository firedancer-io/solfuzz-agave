use clap::Parser;
use solfuzz_agave::elf_generated::{ELFLoaderEffects, ELFLoaderEffectsArgs, ELFLoaderFixture};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn exec(input: &PathBuf, blob: &[u8], builder: &mut flatbuffers::FlatBufferBuilder) -> bool {
    builder.reset();

    let Ok(fixture) = flatbuffers::root::<ELFLoaderFixture<'_>>(blob) else {
        println!("Failed to parse fixture.");
        return false;
    };

    let context = fixture.input();
    let expected = fixture.output();

    solfuzz_agave::elf_loader_flatbuffers::execute_elf_loader(&context, builder);
    let effects_slice = builder.finished_data().to_vec();
    builder.reset();

    // Rebuild expected into a fresh FlatBuffer to get comparable bytes
    let expected_rodata = expected
        .rodata()
        .map(|rodata| builder.create_vector(rodata.bytes()));
    let expected_calldests = expected
        .calldests()
        .map(|calldests| builder.create_vector_from_iter(calldests.iter()));
    let expected_off = ELFLoaderEffects::create(
        builder,
        &ELFLoaderEffectsArgs {
            rodata: expected_rodata,
            text_cnt: expected.text_cnt(),
            text_off: expected.text_off(),
            entry_pc: expected.entry_pc(),
            calldests: expected_calldests,
            err_code: expected.err_code(),
        },
    );
    builder.finish_minimal(expected_off);
    let expected_bytes = builder.finished_data();

    let ok = expected_bytes == effects_slice;
    if ok {
        println!("OK: {:?}", input);
    } else {
        let actual = unsafe { flatbuffers::root_unchecked::<ELFLoaderEffects<'_>>(&effects_slice) };
        println!("FAIL: {:?}", input);
        println!("Expected: {:?}", expected);
        println!("Actual: {:?}", actual);
    }
    ok
}

fn main() {
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1 << 12usize);
    for input in cli.inputs {
        let blob = std::fs::read(&input).unwrap();
        if !exec(&input, &blob, &mut builder) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
