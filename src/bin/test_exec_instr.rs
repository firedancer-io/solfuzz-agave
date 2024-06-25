use clap::Parser;
use prost::Message;
use solfuzz_agave::proto::{AcctState, InstrFixture};
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
    let context_accounts = context.accounts.clone();
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

    // Remove non-modified accounts by comparing each account with input
    let mut modified_accounts = Vec::<AcctState>::new();
    for output_account in effects.modified_accounts.iter() {
        let mut present_in_input = false;
        for input_account in context_accounts.iter() {
            if input_account.address == output_account.address {
                present_in_input = true;
                if input_account != output_account {
                    modified_accounts.push(output_account.clone());
                }
            }
        }
        if !present_in_input {
            modified_accounts.push(output_account.clone());
        }
    }
    let mut pruned_effects = effects.clone();
    pruned_effects.modified_accounts = modified_accounts;

    let ok = pruned_effects == expected;
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
    if fail_cnt > 0 {
        std::process::exit(1);
    }
    std::process::exit(0);
}
