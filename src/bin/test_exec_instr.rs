use clap::Parser;
use prost::Message;
use solfuzz_agave::proto::InstrFixture;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn exec(input: &PathBuf) -> bool {
    let blob = std::fs::read(input).unwrap();
    let fixture = InstrFixture::decode(&blob[..]).unwrap();
    let context = match fixture.input {
        Some(i) => i,
        None => {
            println!("No context found.");
            return false;
        }
    };

    let expected = match fixture.output {
        Some(e) => e,
        None => {
            println!("No fixture found.");
            return false;
        }
    };
    let effects = match solfuzz_agave::execute_instr_proto(context) {
        Some(e) => e,
        None => {
            println!(
                "FAIL: No instruction effects returned for input: {:?}",
                input
            );
            return false;
        }
    };

    let ok = effects == expected;

    if ok {
        println!("OK: {:?}", input);
    } else {
        println!("FAIL: {:?}", input);
    }
    ok
}

fn main() {
    let cli = Cli::parse();
    let mut fail_cnt = 0;
    for input in cli.inputs {
        if !exec(&input) {
            fail_cnt += 1;
        }
    }
    std::process::exit(fail_cnt);
}
