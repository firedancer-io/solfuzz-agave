use clap::Parser;
use solfuzz_agave::vm_generated::{InputDataRegion, SyscallEffects, SyscallFixture};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn compare_byte_vectors(
    exp_vec: Option<flatbuffers::Vector<u8>>,
    act_vec: Option<flatbuffers::Vector<u8>>,
    field_name: &str,
) -> bool {
    match (exp_vec, act_vec) {
        (Some(exp), Some(act)) => {
            let exp_bytes = exp.bytes();
            let act_bytes = act.bytes();
            if exp_bytes != act_bytes {
                println!(
                    "  {}: expected.len()={}, actual.len()={}",
                    field_name,
                    exp_bytes.len(),
                    act_bytes.len()
                );
                return false;
            }
            true
        }
        (None, None) => true,
        // Treat empty vectors same as None
        (None, Some(act)) if act.len() > 0 => {
            println!(
                "  {}: expected=None, actual=Some({} bytes)",
                field_name,
                act.len()
            );
            false
        }
        (Some(exp), None) if exp.len() > 0 => {
            println!(
                "  {}: expected=Some({} bytes), actual=None",
                field_name,
                exp.len()
            );
            false
        }
        _ => true, // Treat empty vector same as None
    }
}

fn compare_input_data_regions(
    exp_regions: Option<flatbuffers::Vector<flatbuffers::ForwardsUOffset<InputDataRegion>>>,
    act_regions: Option<flatbuffers::Vector<flatbuffers::ForwardsUOffset<InputDataRegion>>>,
) -> bool {
    match (exp_regions, act_regions) {
        (Some(exp), Some(act)) => {
            if exp.len() != act.len() {
                println!(
                    "  input_data_regions.len(): expected={}, actual={}",
                    exp.len(),
                    act.len()
                );
                return false;
            }

            let mut all_ok = true;
            for i in 0..exp.len() {
                let exp_region = exp.get(i);
                let act_region = act.get(i);

                if exp_region.offset() != act_region.offset() {
                    println!(
                        "  input_data_regions[{}].offset: expected={}, actual={}",
                        i,
                        exp_region.offset(),
                        act_region.offset()
                    );
                    all_ok = false;
                }

                if exp_region.is_writable() != act_region.is_writable() {
                    println!(
                        "  input_data_regions[{}].is_writable: expected={}, actual={}",
                        i,
                        exp_region.is_writable(),
                        act_region.is_writable()
                    );
                    all_ok = false;
                }

                let exp_bytes = exp_region.content().bytes();
                let act_bytes = act_region.content().bytes();
                if exp_bytes != act_bytes {
                    println!(
                        "  input_data_regions[{}].content: expected.len()={}, actual.len()={}",
                        i,
                        exp_bytes.len(),
                        act_bytes.len()
                    );
                    // Show first 16 bytes of each for debugging
                    let show_len = 16.min(exp_bytes.len()).min(act_bytes.len());
                    if show_len > 0 {
                        println!(
                            "    first {} bytes expected: {:02x?}",
                            show_len,
                            &exp_bytes[..show_len]
                        );
                        println!(
                            "    first {} bytes actual:   {:02x?}",
                            show_len,
                            &act_bytes[..show_len]
                        );
                    }
                    all_ok = false;
                }
            }
            all_ok
        }
        (None, None) => true,
        (None, Some(act)) => {
            println!(
                "  input_data_regions: expected=None, actual=Some({} regions)",
                act.len()
            );
            false
        }
        (Some(exp), None) => {
            println!(
                "  input_data_regions: expected=Some({} regions), actual=None",
                exp.len()
            );
            false
        }
    }
}

fn compare_syscall_effects(
    input: &PathBuf,
    expected: SyscallEffects,
    actual: SyscallEffects,
) -> bool {
    let mut all_ok = true;

    // Compare error codes
    if expected.err_code() != actual.err_code() {
        println!(
            "  err_code: expected={}, actual={}",
            expected.err_code(),
            actual.err_code()
        );
        all_ok = false;
    }

    if expected.err_kind() != actual.err_kind() {
        println!(
            "  err_kind: expected={:?}, actual={:?}",
            expected.err_kind(),
            actual.err_kind()
        );
        all_ok = false;
    }

    // Compare all registers (for syscalls, only r0 is meaningful, but we verify all match)
    let reg_names = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
    ];
    let exp_regs = [
        expected.r0(),
        expected.r1(),
        expected.r2(),
        expected.r3(),
        expected.r4(),
        expected.r5(),
        expected.r6(),
        expected.r7(),
        expected.r8(),
        expected.r9(),
        expected.r10(),
    ];
    let act_regs = [
        actual.r0(),
        actual.r1(),
        actual.r2(),
        actual.r3(),
        actual.r4(),
        actual.r5(),
        actual.r6(),
        actual.r7(),
        actual.r8(),
        actual.r9(),
        actual.r10(),
    ];

    for (i, reg_name) in reg_names.iter().enumerate() {
        if exp_regs[i] != act_regs[i] {
            println!(
                "  {}: expected={:#018x}, actual={:#018x}",
                reg_name, exp_regs[i], act_regs[i]
            );
            all_ok = false;
        }
    }

    // Compare CU available
    if expected.cu_avail() != actual.cu_avail() {
        println!(
            "  cu_avail: expected={}, actual={}",
            expected.cu_avail(),
            actual.cu_avail()
        );
        all_ok = false;
    }

    // Compare PC and frame count
    if expected.pc() != actual.pc() {
        println!(
            "  pc: expected={:#x}, actual={:#x}",
            expected.pc(),
            actual.pc()
        );
        all_ok = false;
    }

    if expected.frame_count() != actual.frame_count() {
        println!(
            "  frame_count: expected={}, actual={}",
            expected.frame_count(),
            actual.frame_count()
        );
        all_ok = false;
    }

    // Compare log (treat empty string same as None)
    match (expected.log(), actual.log()) {
        (Some(exp_log), Some(act_log)) => {
            if exp_log != act_log {
                println!("  log: expected='{}', actual='{}'", exp_log, act_log);
                all_ok = false;
            }
        }
        (None, None) => {}
        (None, Some(act_log)) if !act_log.is_empty() => {
            println!("  log: expected=None, actual='{}'", act_log);
            all_ok = false;
        }
        (Some(exp_log), None) if !exp_log.is_empty() => {
            println!("  log: expected='{}', actual=None", exp_log);
            all_ok = false;
        }
        _ => {} // Treat empty string same as None
    }

    // Compare memory regions
    if !compare_byte_vectors(expected.heap(), actual.heap(), "heap") {
        all_ok = false;
    }

    if !compare_byte_vectors(expected.stack(), actual.stack(), "stack") {
        all_ok = false;
    }

    if !compare_byte_vectors(expected.rodata(), actual.rodata(), "rodata") {
        all_ok = false;
    }

    // Compare input data regions
    if !compare_input_data_regions(expected.input_data_regions(), actual.input_data_regions()) {
        all_ok = false;
    }

    if all_ok {
        println!("OK: {:?}", input);
    } else {
        println!("FAIL: {:?}", input);
    }

    all_ok
}

fn main() {
    unsafe {
        solfuzz_agave::sol_compat_init(0);
    }
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;

    for input in cli.inputs {
        let blob = std::fs::read(&input).unwrap();
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1 << 17);

        let Ok(fixture) = flatbuffers::root::<SyscallFixture<'_>>(&blob) else {
            println!("Failed to parse fixture: {:?}", input);
            fail_cnt = fail_cnt.saturating_add(1);
            continue;
        };

        let context = fixture.input();
        let expected = fixture.output();

        solfuzz_agave::vm_syscalls_flatbuffers::execute_vm_syscall(&context, &mut builder);
        let effects_slice = builder.finished_data().to_vec();

        let actual = unsafe { flatbuffers::root_unchecked::<SyscallEffects<'_>>(&effects_slice) };

        if !compare_syscall_effects(&input, expected, actual) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
