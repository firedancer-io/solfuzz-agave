// This is an auto-generated file. To add entries, edit fd_types.json
use bincode;
use heck::ToSnakeCase;
use serde_yaml;
use solana_accounts_db::blockhash_queue::HashInfo;
use solana_clock::Clock;
use solana_config_program::ConfigKeys;
use solana_core::repair::serve_repair::RepairProtocol;
use solana_core::repair::serve_repair::RepairRequestHeader;
use solana_cost_model::cost_tracker::CostTracker;
use solana_cost_model::transaction_cost::TransactionCost;
use solana_cost_model::transaction_cost::UsageCostDetails;
use solana_epoch_info::EpochInfo;
use solana_epoch_rewards::EpochRewards;
use solana_fee_calculator::FeeCalculator;
use solana_fee_calculator::FeeRateGovernor;
use solana_gossip::crds_data::CrdsData;
use solana_gossip::crds_gossip_pull::CrdsFilter;
use solana_gossip::crds_value::CrdsValue;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_last_restart_slot::LastRestartSlot;
use solana_ledger::blockstore_meta::DuplicateSlotProof;
use solana_ledger::blockstore_meta::FrozenHashStatus;
use solana_ledger::blockstore_meta::FrozenHashVersioned;
use solana_message::AccountKeys;
use solana_poh_config::PohConfig;
use solana_program::sysvar::epoch_schedule::EpochSchedule;
use solana_program::sysvar::fees::Fees;
use solana_program::sysvar::rent::Rent;
use solana_program::sysvar::stake_history::StakeHistory;
use solana_program::sysvar::stake_history::StakeHistoryEntry;
use solana_rent_collector::RentCollector;
use solana_runtime::bank::BankHashStats;
use solana_runtime::epoch_stakes::EpochStakes;
use solana_runtime::epoch_stakes::NodeVoteAccounts;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_runtime::serde_snapshot::BankIncrementalSnapshotPersistence;
use solana_runtime::stakes::Stakes;
use solana_runtime::status_cache::SlotDelta;
use solana_sdk::feature::Feature;
use solana_sdk::signature::Signature;
use solana_svm_conformance::proto::TxnResult;
use solana_vote::vote_account::VoteAccounts;
use std::ffi::c_int;

fn convert_keys_to_snake_case(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut new_map = serde_yaml::Mapping::new();
            for (k, mut v) in std::mem::take(map) {
                let new_key = match k {
                    serde_yaml::Value::String(s) => serde_yaml::Value::String(s.to_snake_case()),
                    _ => k,
                };
                convert_keys_to_snake_case(&mut v);
                new_map.insert(new_key, v);
            }
            *value = serde_yaml::Value::Mapping(new_map);
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                convert_keys_to_snake_case(v);
            }
        }
        _ => {}
    }
}

fn f64_to_hex_string(value: f64) -> String {
    let bytes = value.to_ne_bytes();
    let hex_strings: Vec<String> = bytes
            .iter()
            .map(|b| format!("0x{:02X}", b))
            .collect();
    format!("[{}]", hex_strings.join(","))
}

fn yaml_normalize_float(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (_k, v) in map.iter_mut() {
                yaml_normalize_float(v);
                
                if let serde_yaml::Value::Number(num) = v {
                    if num.is_f64() {
                        let formatted = f64_to_hex_string(num.as_f64().unwrap());
                        *v = serde_yaml::Value::String(formatted);
                    }
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                yaml_normalize_float(item);
            }
        }
        _ => {}
    }
}

pub fn rename_nested_key(
    value: &mut serde_yaml::Value,
    key_path: &[&str],
    new_key: &str,
) -> Result<(), ()> {
    if key_path.is_empty() {
        return Err(());
    }

    if key_path.len() == 1 {
        if let serde_yaml::Value::Mapping(old_map) = value {
            let mut new_map = serde_yaml::Mapping::new();
            let target_key = key_path[0];
            let mut found = false;

            for (k, v) in old_map.iter() {
                if k.as_str() == Some(target_key) {
                    new_map.insert(serde_yaml::Value::String(new_key.to_string()), v.clone());
                    found = true;
                } else {
                    new_map.insert(k.clone(), v.clone());
                }
            }

            if found {
                *value = serde_yaml::Value::Mapping(new_map);
                return Ok(());
            }
        }
        return Err(());
    }

    if let serde_yaml::Value::Mapping(map) = value {
        let current_key = key_path[0];
        if let Some(next_value) = map.get_mut(&serde_yaml::Value::String(current_key.to_string())) {
            return rename_nested_key(next_value, &key_path[1..], new_key);
        }
    }

    Err(())
}

fn yaml_to_string(value: &serde_yaml::Value) -> String {
    let mut s = "".to_string();
    eprintln!("value: {:?}", value);

    match value {
        serde_yaml::Value::Tagged(tagged_value) => {
            let tag = tagged_value.tag.to_string().replace("!", "").to_lowercase();
            s += &format!("{}: \n", tag);
            s += &yaml_to_string(&tagged_value.value);
        },
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map.iter() {
                s += &format!("{}: ", k.as_str().unwrap());
                if let serde_yaml::Value::Mapping(_) = v {
                    s += "\n";
                }
                s += &yaml_to_string(v);;
                if !s.ends_with("\n") {
                    s += "\n";
                }
            }
        },
        serde_yaml::Value::Sequence(seq) => {
            if seq.is_empty() {
                s += "[]";
            } else {
                for v in seq {
                    s += "- ";
                    s += &yaml_to_string(v);
                    s += "\n";
                }
            }
        }
        serde_yaml::Value::Number(num) => {
            if num.is_u64() {
                s += &format!("{}", num.as_u64().unwrap());
            } else if num.is_i64() {
                s += &format!("{}", num.as_i64().unwrap());
            } else {
                panic!("f64 should have been normalized: {:?}", value);
            }
        },
        serde_yaml::Value::Bool(b) => {
            s += &format!("{}", b);
        },
        serde_yaml::Value::String(s2) => {
            s += &format!("{}\n", s2);
        },
        serde_yaml::Value::Null => {
            s += "null\n";
        },
    }

    s
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_type_execute_v1(
    out_yaml_ptr: *mut u8,
    out_yaml_psz: *mut u64,
    in_bincode_ptr: *mut u8,
    in_bincode_sz: u64,
) -> c_int {
    if in_bincode_sz == 0 {
        return 0;
    }

    let bincode_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(in_bincode_ptr, in_bincode_sz as usize)
    };

    match bincode_slice[0] {
        0 => {
            let typ: Hash = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        2 => {
            let typ: Signature = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        5 => {
            let typ: Feature = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        6 => {
            let typ: FeeCalculator = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        7 => {
            let typ: HashInfo = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        11 => {
            let typ: FeeRateGovernor = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        16 => {
            let typ: EpochSchedule = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        33 => {
            let typ: BankIncrementalSnapshotPersistence = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        42 => {
            let typ: BankHashStats = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        56 => {
            let typ: PohConfig = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        60 => {
            let typ: Clock = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        61 => {
            let typ: LastRestartSlot = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            rename_nested_key(&mut value, &["last_restart_slot"], "slot").unwrap();
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        93 => {
            let typ: Fees = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        94 => {
            let typ: EpochRewards = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        157 => {
            let typ: FrozenHashStatus = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut value = serde_yaml::to_value(&typ).unwrap();
            convert_keys_to_snake_case(&mut value);
            yaml_normalize_float(&mut value);
            let mut yaml_str = yaml_to_string(&value);
            if !yaml_str.ends_with("\n") { yaml_str += "\n"; }
            let sz = yaml_str.len();
            unsafe {
                *out_yaml_psz = sz as u64;
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_yaml_ptr, sz);
            }
        }
        _ => return 0,
    };
    1
}
