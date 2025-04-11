// This is an auto-generated file. To add entries, edit fd_types.json
use bincode;
use serde::Serialize;
use solana_accounts_db::blockhash_queue::HashInfo;
use solana_clock::Clock;
use solana_config_program::ConfigKeys;
use solana_core::repair::serve_repair::RepairProtocol;
use solana_epoch_rewards::EpochRewards;
use solana_fee_calculator::FeeCalculator;
use solana_fee_calculator::FeeRateGovernor;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_last_restart_slot::LastRestartSlot;
use solana_ledger::blockstore_meta::FrozenHashStatus;
use solana_ledger::blockstore_meta::FrozenHashVersioned;
use solana_poh_config::PohConfig;
use solana_program::sysvar::epoch_schedule::EpochSchedule;
use solana_program::sysvar::rent::Rent;
use solana_program::sysvar::stake_history::StakeHistory;
use solana_program::sysvar::stake_history::StakeHistoryEntry;
use solana_rent_collector::RentCollector;
use solana_runtime::bank::BankHashStats;
use solana_runtime::epoch_stakes::NodeVoteAccounts;
use solana_runtime::serde_snapshot::BankIncrementalSnapshotPersistence;
use solana_sdk::feature::Feature;
use solana_sdk::signature::Signature;
use solana_vote::vote_account::VoteAccounts;
use solana_runtime::epoch_stakes::EpochStakes;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_gossip::crds_data::CrdsData;
use solana_gossip::crds_gossip_pull::CrdsFilter;
use solana_gossip::crds_value::CrdsValue;
use solana_core::repair::serve_repair::RepairRequestHeader;
use solana_ledger::blockstore_meta::DuplicateSlotProof;
use std::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_type_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
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

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        2 => {
            let typ: Signature = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        5 => {
            let typ: Feature = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        6 => {
            let typ: FeeCalculator = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        7 => {
            let typ: HashInfo = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        11 => {
            let typ: FeeRateGovernor = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        13 => {
            let typ: HardForks = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        14 => {
            let typ: Inflation = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        15 => {
            let typ: Rent = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        16 => {
            let typ: EpochSchedule = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        17 => {
            let typ: RentCollector = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        18 => {
            let typ: StakeHistoryEntry = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        19 => {
            let typ: StakeHistory = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        22 => {
            let typ: VoteAccounts = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        33 => {
            let typ: BankIncrementalSnapshotPersistence = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        34 => {
            let typ: NodeVoteAccounts = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        37 => {
            let typ: EpochStakes = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        42 => {
            let typ: BankHashStats = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        50 => {
            let typ: VersionedEpochStakes = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        56 => {
            let typ: PohConfig = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        60 => {
            let typ: Clock = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        61 => {
            let typ: LastRestartSlot = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        94 => {
            let typ: EpochRewards = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        155 => {
            let typ: ConfigKeys = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        171 => {
            let typ: FrozenHashStatus = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        172 => {
            let typ: FrozenHashVersioned = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        213 => {
            let typ: CrdsData = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        215 => {
            let typ: CrdsFilter = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        216 => {
            let typ: CrdsValue = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        225 => {
            let typ: RepairRequestHeader = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        230 => {
            let typ: RepairProtocol = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        245 => {
            let typ: DuplicateSlotProof = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {
                h
            } else {
                return 0;
            };

            let mut ser = crate::serializer::CustomSerializer::new();
            typ.serialize(&mut ser).unwrap();
            let ser_sz = ser.output.len();
            let yaml_str = serde_yaml::to_string(&typ).unwrap();
            let yaml_sz = yaml_str.len();
            unsafe {
                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;
                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, 1);
                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.add(std::mem::size_of::<u64>()), ser_sz);
                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.add(std::mem::size_of::<u64>() + ser_sz), yaml_sz);
            }
        }
        _ => return 0,
    };
    1
}
