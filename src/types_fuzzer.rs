// This is an auto-generated file. To add entries, edit fd_types.json
use crate::memory_representation_serializer::MemoryRepresentationSerializer;
use crate::proto::{TypeContext, TypeEffects};
use bincode;
use bincode::Options;
use prost::Message;
use serde::Serialize;
use solana_accounts_db::blockhash_queue::HashInfo;
use solana_clock::Clock;
use solana_config_program::ConfigKeys;
use solana_core::repair::serve_repair::RepairProtocol;
use solana_core::repair::serve_repair::RepairRequestHeader;
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
use solana_poh_config::PohConfig;
use solana_program::sysvar::epoch_schedule::EpochSchedule;
use solana_program::sysvar::rent::Rent;
use solana_program::sysvar::stake_history::StakeHistory;
use solana_program::sysvar::stake_history::StakeHistoryEntry;
use solana_rent_collector::RentCollector;
use solana_runtime::bank::BankHashStats;
use solana_runtime::epoch_stakes::EpochStakes;
use solana_runtime::epoch_stakes::NodeVoteAccounts;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_runtime::serde_snapshot::BankIncrementalSnapshotPersistence;
use solana_sdk::feature::Feature;
use solana_sdk::signature::Signature;
use solana_vote::vote_account::VoteAccounts;
use std::ffi::c_int;

use std::alloc::{GlobalAlloc, Layout, System};

// Define a custom allocator that can detect and handle large allocations
struct LimitedAllocator {
    inner: System,
}

unsafe impl GlobalAlloc for LimitedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Set a reasonable maximum allocation size
        const MAX_ALLOC: usize = 10 * 1024 * 1024; // 10 MB

        if layout.size() > MAX_ALLOC {
            println!("ASDF ALLOCATION OF {} BYTES EXCEEDS LIMIT OF {} BYTES", layout.size(), MAX_ALLOC);
            panic!(
                "Allocation of {} bytes exceeds limit of {} bytes",
                layout.size(),
                MAX_ALLOC
            );
        } else {
            self.inner.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout)
    }
}

// Install our custom allocator as the global allocator
#[global_allocator]
static ALLOCATOR: LimitedAllocator = LimitedAllocator { inner: System };

#[no_mangle]
pub unsafe extern "C" fn sol_compat_type_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let type_ctx = match TypeContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let type_effects = match execute_type(type_ctx) {
        Some(effects) => effects,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = type_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

fn process_type<T: Serialize + serde::de::DeserializeOwned>(
    bincode_slice: &[u8],
) -> Option<TypeEffects> {
    // Create bincode configuration with size limits
    let config = bincode::config::DefaultOptions::new()
        .with_limit(10_000_000) // Limit to 10MB (adjust as needed)
        .with_fixint_encoding()
        .allow_trailing_bytes();

    let res = config.deserialize::<T>(&bincode_slice[1..]);
    let typ = match res {
        Ok(h) => { h }
        Err(err) => {
            println!("ASDF TYPE SERIALIZE FAILED: {}", err);
            return Some(TypeEffects {
                result: 1,
                ..Default::default()
            });
        }
    };

    let mut ser = MemoryRepresentationSerializer::new();
    let out = typ.serialize(&mut ser);
    match out {
        Ok(_) => {}
        Err(_e) => {
            return Some(TypeEffects {
                result: 1,
                ..Default::default()
            });
        }
    }

    let yaml_str = serde_yaml::to_string(&typ).unwrap_or_default();

    Some(TypeEffects {
        result: 0,
        representation: ser.output.into_bytes(),
        yaml: yaml_str.as_bytes().to_vec(),
    })
}

pub fn execute_type(input: TypeContext) -> Option<TypeEffects> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if input.content.is_empty() {
            return None;
        }

        let bincode_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(input.content.as_ptr(), input.content.len()) };

        println!("ASDF TYPE ID: {} {:?}", bincode_slice[0], bincode_slice.len());
        /* FIXME: This type lookup table is AWFUL and needs to be
           replaced with something that doesn't have hardcoded indices. */
        match bincode_slice[0] {
            0 => process_type::<Hash>(bincode_slice),
            2 => process_type::<Signature>(bincode_slice),
            5 => process_type::<Feature>(bincode_slice),
            6 => process_type::<FeeCalculator>(bincode_slice),
            7 => process_type::<HashInfo>(bincode_slice),
            11 => process_type::<FeeRateGovernor>(bincode_slice),
            13 => process_type::<HardForks>(bincode_slice),
            14 => process_type::<Inflation>(bincode_slice),
            15 => process_type::<Rent>(bincode_slice),
            16 => process_type::<EpochSchedule>(bincode_slice),
            17 => process_type::<RentCollector>(bincode_slice),
            18 => process_type::<StakeHistoryEntry>(bincode_slice),
            20 => process_type::<StakeHistory>(bincode_slice),
            21 => process_type::<VoteAccounts>(bincode_slice),
            34 => process_type::<BankIncrementalSnapshotPersistence>(bincode_slice),
            35 => process_type::<NodeVoteAccounts>(bincode_slice),
            38 => process_type::<EpochStakes>(bincode_slice),
            43 => process_type::<BankHashStats>(bincode_slice),
            51 => process_type::<VersionedEpochStakes>(bincode_slice),
            57 => process_type::<PohConfig>(bincode_slice),
            61 => process_type::<Clock>(bincode_slice),
            62 => process_type::<LastRestartSlot>(bincode_slice),
            95 => process_type::<EpochRewards>(bincode_slice),
            156 => process_type::<ConfigKeys>(bincode_slice),
            172 => process_type::<FrozenHashStatus>(bincode_slice),
            173 => process_type::<FrozenHashVersioned>(bincode_slice),
            214 => process_type::<CrdsData>(bincode_slice),
            216 => process_type::<CrdsFilter>(bincode_slice),
            217 => process_type::<CrdsValue>(bincode_slice),
            226 => process_type::<RepairRequestHeader>(bincode_slice),
            231 => process_type::<RepairProtocol>(bincode_slice),
            246 => process_type::<DuplicateSlotProof>(bincode_slice),
            _ => {
                eprintln!("Invalid type ID: {}", bincode_slice[0]);
                None
            }
        }
    }));

    // Handle any panic that might have occurred
    match result {
        Ok(effects) => effects,
        Err(_) => Some(TypeEffects {
            result: 1,
            ..Default::default()
        }),
    }
}
