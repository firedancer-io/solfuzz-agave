use clap::Parser;
use prost::Message;
use solfuzz_agave::proto::BlockFixture;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn exec(input: &PathBuf) -> bool {
    let blob = std::fs::read(input).unwrap();
    let fixture = BlockFixture::decode(&blob[..]).unwrap();
    let Some(context) = fixture.input else {
        println!("No context found.");
        return false;
    };

    let Some(expected) = fixture.output else {
        println!("No fixture found.");
        return false;
    };
    let Some(effects) = solfuzz_agave::block::execute_block(context) else {
        println!("FAIL: No block effects returned for input: {:?}", input);
        return false;
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
    unsafe {
        solfuzz_agave::sol_compat_init(0);
    }
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;
    for input in cli.inputs {
        if !exec(&input) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
