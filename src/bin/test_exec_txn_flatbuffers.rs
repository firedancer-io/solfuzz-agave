use clap::Parser;
use solfuzz_agave::context_generated::Account;
use solfuzz_agave::txn_generated::{FeeDetails, TxnEffects, TxnFixture};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn compare_accounts(exp_acct: &Account, act_acct: &Account, path: &str) -> bool {
    let mut ok = true;

    // Compare address
    if exp_acct.address().0 != act_acct.address().0 {
        println!(
            "  {}.address: expected={:?}, actual={:?}",
            path,
            exp_acct.address().0,
            act_acct.address().0
        );
        ok = false;
    }

    // Compare lamports
    if exp_acct.lamports() != act_acct.lamports() {
        println!(
            "  {}.lamports: expected={}, actual={}",
            path,
            exp_acct.lamports(),
            act_acct.lamports()
        );
        ok = false;
    }

    // Compare data
    let exp_data = exp_acct.data().bytes();
    let act_data = act_acct.data().bytes();
    if exp_data != act_data {
        println!(
            "  {}.data: expected.len()={}, actual.len()={}",
            path,
            exp_data.len(),
            act_data.len()
        );
        if exp_data.len() == act_data.len() {
            // Same length but different content - show first difference
            for (i, (e, a)) in exp_data.iter().zip(act_data.iter()).enumerate() {
                if e != a {
                    println!(
                        "  {}.data[{}]: expected={:#04x}, actual={:#04x}",
                        path, i, e, a
                    );
                    break;
                }
            }
        }
        ok = false;
    }

    // Compare executable
    if exp_acct.executable() != act_acct.executable() {
        println!(
            "  {}.executable: expected={}, actual={}",
            path,
            exp_acct.executable(),
            act_acct.executable()
        );
        ok = false;
    }

    // Compare owner
    if exp_acct.owner().0 != act_acct.owner().0 {
        println!(
            "  {}.owner: expected={:?}, actual={:?}",
            path,
            exp_acct.owner().0,
            act_acct.owner().0
        );
        ok = false;
    }

    ok
}

fn compare_fee_details(expected: Option<FeeDetails>, actual: Option<FeeDetails>) -> bool {
    match (expected, actual) {
        (Some(exp_fd), Some(act_fd)) => {
            let mut ok = true;
            if exp_fd.transaction_fee() != act_fd.transaction_fee() {
                println!(
                    "  fee_details.transaction_fee: expected={}, actual={}",
                    exp_fd.transaction_fee(),
                    act_fd.transaction_fee()
                );
                ok = false;
            }
            if exp_fd.prioritization_fee() != act_fd.prioritization_fee() {
                println!(
                    "  fee_details.prioritization_fee: expected={}, actual={}",
                    exp_fd.prioritization_fee(),
                    act_fd.prioritization_fee()
                );
                ok = false;
            }
            ok
        }
        (None, Some(_)) => {
            println!("  fee_details: expected=None, actual=Some(...)");
            false
        }
        (Some(_), None) => {
            println!("  fee_details: expected=Some(...), actual=None");
            false
        }
        (None, None) => true,
    }
}

fn compare_txn_effects(input: &PathBuf, expected: TxnEffects, actual: TxnEffects) -> bool {
    let mut all_ok = true;

    // Compare error codes
    if expected.txn_err_code() != actual.txn_err_code() {
        println!(
            "  txn_err_code: expected={}, actual={}",
            expected.txn_err_code(),
            actual.txn_err_code()
        );
        all_ok = false;
    }

    if expected.instr_err_code() != actual.instr_err_code() {
        println!(
            "  instr_err_code: expected={}, actual={}",
            expected.instr_err_code(),
            actual.instr_err_code()
        );
        all_ok = false;
    }

    if expected.instr_err_idx() != actual.instr_err_idx() {
        println!(
            "  instr_err_idx: expected={}, actual={}",
            expected.instr_err_idx(),
            actual.instr_err_idx()
        );
        all_ok = false;
    }

    if expected.custom_err_code() != actual.custom_err_code() {
        println!(
            "  custom_err_code: expected={}, actual={}",
            expected.custom_err_code(),
            actual.custom_err_code()
        );
        all_ok = false;
    }

    // Compare execution metrics
    if expected.executed_units() != actual.executed_units() {
        println!(
            "  executed_units: expected={}, actual={}",
            expected.executed_units(),
            actual.executed_units()
        );
        all_ok = false;
    }

    if expected.loaded_accounts_data_size() != actual.loaded_accounts_data_size() {
        println!(
            "  loaded_accounts_data_size: expected={}, actual={}",
            expected.loaded_accounts_data_size(),
            actual.loaded_accounts_data_size()
        );
        all_ok = false;
    }

    // Compare return data byte-by-byte
    match (expected.return_data(), actual.return_data()) {
        (Some(exp_data), Some(act_data)) => {
            let exp_bytes = exp_data.bytes();
            let act_bytes = act_data.bytes();
            if exp_bytes != act_bytes {
                println!(
                    "  return_data: expected.len()={}, actual.len()={}",
                    exp_bytes.len(),
                    act_bytes.len()
                );
                if exp_bytes.len() == act_bytes.len() && exp_bytes.len() <= 64 {
                    // Show full data if small enough
                    println!("  return_data.expected: {:?}", exp_bytes);
                    println!("  return_data.actual: {:?}", act_bytes);
                } else if exp_bytes.len() == act_bytes.len() {
                    // Show first difference
                    for (i, (e, a)) in exp_bytes.iter().zip(act_bytes.iter()).enumerate() {
                        if e != a {
                            println!(
                                "  return_data[{}]: expected={:#04x}, actual={:#04x}",
                                i, e, a
                            );
                            break;
                        }
                    }
                }
                all_ok = false;
            }
        }
        (None, Some(act_data)) => {
            println!(
                "  return_data: expected=None, actual=Some({} bytes)",
                act_data.bytes().len()
            );
            all_ok = false;
        }
        (Some(exp_data), None) => {
            println!(
                "  return_data: expected=Some({} bytes), actual=None",
                exp_data.bytes().len()
            );
            all_ok = false;
        }
        (None, None) => {}
    }

    // Compare fee details
    if !compare_fee_details(expected.fee_details(), actual.fee_details()) {
        all_ok = false;
    }

    // Compare modified accounts - every field recursively
    match (expected.modified_accounts(), actual.modified_accounts()) {
        (Some(exp_accts), Some(act_accts)) => {
            if exp_accts.len() != act_accts.len() {
                println!(
                    "  modified_accounts.len(): expected={}, actual={}",
                    exp_accts.len(),
                    act_accts.len()
                );
                all_ok = false;
            } else {
                // Compare each account field-by-field
                for i in 0..exp_accts.len() {
                    let exp_acct = exp_accts.get(i);
                    let act_acct = act_accts.get(i);
                    let path = format!("modified_accounts[{}]", i);
                    if !compare_accounts(&exp_acct, &act_acct, &path) {
                        all_ok = false;
                    }
                }
            }
        }
        (None, Some(act_accts)) => {
            println!(
                "  modified_accounts: expected=None, actual=Some({} accounts)",
                act_accts.len()
            );
            all_ok = false;
        }
        (Some(exp_accts), None) => {
            println!(
                "  modified_accounts: expected=Some({} accounts), actual=None",
                exp_accts.len()
            );
            all_ok = false;
        }
        (None, None) => {}
    }

    if all_ok {
        println!("OK: {:?}", input);
    } else {
        println!("FAIL: {:?}", input);
    }

    all_ok
}

fn exec(input: &PathBuf, blob: &[u8], builder: &mut flatbuffers::FlatBufferBuilder) -> bool {
    builder.reset();

    let Ok(fixture) = flatbuffers::root::<TxnFixture<'_>>(blob) else {
        println!("Failed to parse fixture.");
        return false;
    };

    let context = fixture.input();
    let expected = fixture.output();

    solfuzz_agave::transaction_flatbuffers::execute_transaction(&context, builder);
    let effects_slice = builder.finished_data().to_vec();

    let actual = unsafe { flatbuffers::root_unchecked::<TxnEffects<'_>>(&effects_slice) };

    compare_txn_effects(input, expected, actual)
}

fn main() {
    unsafe {
        solfuzz_agave::sol_compat_init(0);
    }
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1 << 17);
    for input in cli.inputs {
        println!("Processing: {:?}", input);
        let blob = std::fs::read(&input).unwrap();
        if !exec(&input, &blob, &mut builder) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
