use clap::Parser;
use solana_hash::Hash;
use solfuzz_agave::block_generated::{
    BlockEffects, BlockFixture, CostTracker, LeaderScheduleEffects,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

fn compare_cost_tracker(expected: Option<CostTracker>, actual: Option<CostTracker>) -> bool {
    match (expected, actual) {
        (Some(exp_ct), Some(act_ct)) => {
            let mut ok = true;
            if exp_ct.block_cost() != act_ct.block_cost() {
                println!(
                    "  cost_tracker.block_cost: expected={}, actual={}",
                    exp_ct.block_cost(),
                    act_ct.block_cost()
                );
                ok = false;
            }
            if exp_ct.vote_cost() != act_ct.vote_cost() {
                println!(
                    "  cost_tracker.vote_cost: expected={}, actual={}",
                    exp_ct.vote_cost(),
                    act_ct.vote_cost()
                );
                ok = false;
            }
            ok
        }
        (None, Some(_)) => {
            println!("  cost_tracker: expected=None, actual=Some(...)");
            false
        }
        (Some(_), None) => {
            println!("  cost_tracker: expected=Some(...), actual=None");
            false
        }
        (None, None) => true,
    }
}

fn compare_leader_schedule(
    expected: Option<LeaderScheduleEffects>,
    actual: Option<LeaderScheduleEffects>,
) -> bool {
    match (expected, actual) {
        (Some(exp_ls), Some(act_ls)) => {
            let mut ok = true;
            if exp_ls.leaders_epoch() != act_ls.leaders_epoch() {
                println!(
                    "  leader_schedule.leaders_epoch: expected={}, actual={}",
                    exp_ls.leaders_epoch(),
                    act_ls.leaders_epoch()
                );
                ok = false;
            }
            if exp_ls.leaders_slot0() != act_ls.leaders_slot0() {
                println!(
                    "  leader_schedule.leaders_slot0: expected={}, actual={}",
                    exp_ls.leaders_slot0(),
                    act_ls.leaders_slot0()
                );
                ok = false;
            }
            if exp_ls.leaders_slot_cnt() != act_ls.leaders_slot_cnt() {
                println!(
                    "  leader_schedule.leaders_slot_cnt: expected={}, actual={}",
                    exp_ls.leaders_slot_cnt(),
                    act_ls.leaders_slot_cnt()
                );
                ok = false;
            }
            if exp_ls.leader_pub_cnt() != act_ls.leader_pub_cnt() {
                println!(
                    "  leader_schedule.leader_pub_cnt: expected={}, actual={}",
                    exp_ls.leader_pub_cnt(),
                    act_ls.leader_pub_cnt()
                );
                ok = false;
            }
            if exp_ls.leaders_sched_cnt() != act_ls.leaders_sched_cnt() {
                println!(
                    "  leader_schedule.leaders_sched_cnt: expected={}, actual={}",
                    exp_ls.leaders_sched_cnt(),
                    act_ls.leaders_sched_cnt()
                );
                ok = false;
            }
            let exp_hash = exp_ls.leader_schedule_hash().hash();
            let act_hash = act_ls.leader_schedule_hash().hash();
            let hashes_match = (0..16).all(|i| exp_hash.get(i) == act_hash.get(i));
            if !hashes_match {
                let exp_bytes: Vec<u8> = (0..16).map(|i| exp_hash.get(i)).collect();
                let act_bytes: Vec<u8> = (0..16).map(|i| act_hash.get(i)).collect();
                println!(
                    "  leader_schedule.leader_schedule_hash: expected={:?}, actual={:?}",
                    exp_bytes, act_bytes
                );
                ok = false;
            }
            ok
        }
        (None, Some(_)) => {
            println!("  leader_schedule: expected=None, actual=Some(...)");
            false
        }
        (Some(_), None) => {
            println!("  leader_schedule: expected=Some(...), actual=None");
            false
        }
        (None, None) => true,
    }
}

fn compare_block_effects(input: &PathBuf, expected: BlockEffects, actual: BlockEffects) -> bool {
    let mut all_ok = true;

    // Compare has_err
    if expected.has_err() != actual.has_err() {
        println!(
            "  has_err: expected={}, actual={}",
            expected.has_err(),
            actual.has_err()
        );
        all_ok = false;
    }

    // Compare slot_capitalization
    if expected.slot_capitalization() != actual.slot_capitalization() {
        println!(
            "  slot_capitalization: expected={}, actual={}",
            expected.slot_capitalization(),
            actual.slot_capitalization()
        );
        all_ok = false;
    }

    // Compare bank_hash
    match (expected.bank_hash(), actual.bank_hash()) {
        (Some(exp_h), Some(act_h)) => {
            let exp_hash: Hash = exp_h.into();
            let act_hash: Hash = act_h.into();

            if exp_hash != act_hash {
                println!("  bank_hash: expected={}, actual={}", exp_hash, act_hash);
                all_ok = false;
            }
        }
        (None, Some(_)) => {
            println!("  bank_hash: expected=None, actual=Some(...)");
            all_ok = false;
        }
        (Some(_), None) => {
            println!("  bank_hash: expected=Some(...), actual=None");
            all_ok = false;
        }
        (None, None) => {}
    }

    // Compare complex structures
    if !compare_cost_tracker(expected.cost_tracker(), actual.cost_tracker()) {
        all_ok = false;
    }
    if !compare_leader_schedule(expected.leader_schedule(), actual.leader_schedule()) {
        all_ok = false;
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

    let Ok(fixture) = flatbuffers::root::<BlockFixture<'_>>(blob) else {
        println!("Failed to parse fixture.");
        return false;
    };

    let context = fixture.input();
    let expected = fixture.output();

    solfuzz_agave::block_flatbuffers::execute_block(&context, builder);
    let effects_slice = builder.finished_data().to_vec();

    let actual = unsafe { flatbuffers::root_unchecked::<BlockEffects<'_>>(&effects_slice) };

    compare_block_effects(input, expected, actual)
}

fn main() {
    let cli = Cli::parse();
    let mut fail_cnt: i32 = 0;
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1 << 17);
    for input in cli.inputs {
        let blob = std::fs::read(&input).unwrap();
        if !exec(&input, &blob, &mut builder) {
            fail_cnt = fail_cnt.saturating_add(1);
        }
    }
    std::process::exit(fail_cnt);
}
