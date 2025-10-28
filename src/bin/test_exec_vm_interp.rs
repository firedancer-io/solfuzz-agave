use clap::Parser;
use prost::Message;
use solfuzz_agave::proto::SyscallFixture;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,

    /// Pretty print expected and actual effects for diffing
    #[arg(long)]
    print: bool,
}

fn pretty_print_effects(label: &str, effects: &solfuzz_agave::proto::SyscallEffects) {
    println!("=== {} ===", label);
    println!("err_code: {}", effects.error);
    println!("err_kind: <protobuf-no-field>");
    println!("cu_avail: {}", effects.cu_avail);
    println!("frame_count: {}", effects.frame_count);
    println!("pc: {:#018x}", effects.pc);

    // Registers
    println!("r0:  {:#018x}", effects.r0);
    println!("r1:  {:#018x}", effects.r1);
    println!("r2:  {:#018x}", effects.r2);
    println!("r3:  {:#018x}", effects.r3);
    println!("r4:  {:#018x}", effects.r4);
    println!("r5:  {:#018x}", effects.r5);
    println!("r6:  {:#018x}", effects.r6);
    println!("r7:  {:#018x}", effects.r7);
    println!("r8:  {:#018x}", effects.r8);
    println!("r9:  {:#018x}", effects.r9);
    println!("r10: {:#018x}", effects.r10);

    // Log
    if effects.log.is_empty() {
        println!("log: <empty>");
    } else {
        println!("log: '{}'", String::from_utf8_lossy(&effects.log));
    }

    // Memory regions
    println!("heap: {} bytes", effects.heap.len());
    if !effects.heap.is_empty() {
        let show = 32.min(effects.heap.len());
        println!("  first {} bytes: {:02x?}", show, &effects.heap[..show]);
    }

    println!("stack: {} bytes", effects.stack.len());
    if !effects.stack.is_empty() {
        let show = 32.min(effects.stack.len());
        println!("  first {} bytes: {:02x?}", show, &effects.stack[..show]);
    }

    println!("rodata: {} bytes", effects.rodata.len());
    if !effects.rodata.is_empty() {
        let show = 32.min(effects.rodata.len());
        println!("  first {} bytes: {:02x?}", show, &effects.rodata[..show]);
    }

    // Input data regions
    if effects.input_data_regions.is_empty() {
        println!("input_data_regions: <none>");
    } else {
        println!("input_data_regions: {} regions", effects.input_data_regions.len());
        for (i, region) in effects.input_data_regions.iter().enumerate() {
            println!("  region[{}]:", i);
            println!("    offset: {}", region.offset);
            println!("    is_writable: {}", region.is_writable);
            println!("    content: {} bytes", region.content.len());
            let show = 64.min(region.content.len());
            if show > 0 {
                println!("      first {} bytes: {:02x?}", show, &region.content[..show]);
            }
        }
    }
    println!();
}

fn exec(input: &PathBuf, print: bool) -> bool {
    let blob = std::fs::read(input).unwrap();
    let fixture = SyscallFixture::decode(&blob[..]).unwrap();
    let Some(context) = fixture.input else {
        println!("No context found.");
        return false;
    };

    let Some(expected) = fixture.output else {
        println!("No fixture found.");
        return false;
    };
    let Some(effects) = solfuzz_agave::vm_interp::execute_vm_interp(context) else {
        println!(
            "FAIL: No instruction effects returned for input: {:?}",
            input
        );
        return false;
    };

    if print {
        println!("\n{}", "=".repeat(80));
        println!("FILE: {:?}", input);
        println!("{}", "=".repeat(80));
        pretty_print_effects("EXPECTED", &expected);
        pretty_print_effects("ACTUAL", &effects);
        return true; // Don't compare when printing
    }

    let ok = effects == expected;
    if ok {
        println!("OK: {:?}", input);
    } else {
        println!("FAIL: {:?}", input);
        println!("Expected: {:?}", expected);
        println!("Actual: {:?}", effects);
    }
    ok
}

fn main() {
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;
    for input in cli.inputs {
        if !exec(&input, cli.print) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
