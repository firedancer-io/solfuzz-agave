# Example usage:

# python3 scripts/generate_types_map.py ../firedancer/src/flamenco/types/{fd_types.json,fd_types_reflect_generated.c} src/types/types_map_generated.rs

import argparse
import json
import dataclasses

@dataclasses.dataclass
class RustTypeInfo:
    type_name: str
    dep_str: str

# maps fd_types.json entries to Rust types
# also serves as the whitelist for types supported by the harness
fd_rust_types_map = {
  "hash": RustTypeInfo(
    type_name = "Hash",
    dep_str   = "solana_hash::Hash"
  ),
  "signature": RustTypeInfo(
    type_name = "Signature",
    dep_str   = "solana_signature::Signature"
  ),
  "feature": RustTypeInfo(
    type_name = "Feature",
    dep_str   = "solana_feature_gate_interface::Feature"
  ),
  "fee_calculator": RustTypeInfo(
    type_name = "FeeCalculator",
    dep_str   = "solana_fee_calculator::FeeCalculator"
  ),
  "hash_age": RustTypeInfo(
    type_name = "HashInfo",
    dep_str   = "solana_accounts_db::blockhash_queue::HashInfo"
  ),
  "fee_rate_governor": RustTypeInfo(
    type_name = "FeeRateGovernor",
    dep_str   = "solana_fee_calculator::FeeRateGovernor"
  ),
  "hard_forks": RustTypeInfo(
    type_name = "HardForks",
    dep_str   = "solana_hard_forks::HardForks"
  ),
  "inflation": RustTypeInfo(
    type_name = "Inflation",
    dep_str   = "solana_inflation::Inflation"
  ),
  "rent": RustTypeInfo(
    type_name = "Rent",
    dep_str   = "solana_sysvar::rent::Rent"
  ),
  "epoch_schedule": RustTypeInfo(
    type_name = "EpochSchedule",
    dep_str   = "solana_sysvar::epoch_schedule::EpochSchedule"
  ),
  "rent_collector": RustTypeInfo(
    type_name = "RentCollector",
    dep_str   = "solana_rent_collector::RentCollector"
  ),
  "stake_history_entry": RustTypeInfo(
    type_name = "StakeHistoryEntry",
    dep_str   = "solana_sysvar::stake_history::StakeHistoryEntry"
  ),
  "vote_accounts": RustTypeInfo(
    type_name = "VoteAccounts",
    dep_str   = "solana_vote::vote_account::VoteAccounts"
  ),
  "bank_incremental_snapshot_persistence": RustTypeInfo(
    type_name = "BankIncrementalSnapshotPersistence",
    dep_str   = "solana_runtime::serde_snapshot::BankIncrementalSnapshotPersistence"
  ),
  "node_vote_accounts": RustTypeInfo(
    type_name = "NodeVoteAccounts",
    dep_str   = "solana_runtime::epoch_stakes::NodeVoteAccounts"
  ),
  "epoch_stakes": RustTypeInfo(
    type_name = "EpochStakes",
    dep_str   = "solana_runtime::epoch_stakes::EpochStakes"
  ),
  "bank_hash_stats": RustTypeInfo(
    type_name = "BankHashStats",
    dep_str   = "solana_runtime::bank::BankHashStats"
  ),
  "versioned_epoch_stakes": RustTypeInfo(
    type_name = "VersionedEpochStakes",
    dep_str   = "solana_runtime::epoch_stakes::VersionedEpochStakes"
  ),
  "poh_config": RustTypeInfo(
    type_name = "PohConfig",
    dep_str   = "solana_poh_config::PohConfig"
  ),
  "sol_sysvar_clock": RustTypeInfo(
    type_name = "Clock",
    dep_str   = "solana_clock::Clock"
  ),
  "sol_sysvar_last_restart_slot": RustTypeInfo(
    type_name = "LastRestartSlot",
    dep_str   = "solana_last_restart_slot::LastRestartSlot"
  ),
  "sysvar_epoch_rewards": RustTypeInfo(
    type_name = "EpochRewards",
    dep_str   = "solana_epoch_rewards::EpochRewards"
  ),
  "config_keys": RustTypeInfo(
    type_name = "ConfigKeys",
    dep_str   = "solana_config_program::ConfigKeys"
  ),
  "frozen_hash_status": RustTypeInfo(
    type_name = "FrozenHashStatus",
    dep_str   = "solana_ledger::blockstore_meta::FrozenHashStatus"
  ),
  "frozen_hash_versioned": RustTypeInfo(
    type_name = "FrozenHashVersioned",
    dep_str   = "solana_ledger::blockstore_meta::FrozenHashVersioned"
  ),
  "crds_data": RustTypeInfo(
    type_name = "CrdsData",
    dep_str   = "solana_gossip::crds_data::CrdsData"
  ),
  "crds_filter": RustTypeInfo(
    type_name = "CrdsFilter",
    dep_str   = "solana_gossip::crds_gossip_pull::CrdsFilter"
  ),
  "crds_value": RustTypeInfo(
    type_name = "CrdsValue",
    dep_str   = "solana_gossip::crds_value::CrdsValue"
  ),
  "repair_request_header": RustTypeInfo(
    type_name = "RepairRequestHeader",
    dep_str   = "solana_core::repair::serve_repair::RepairRequestHeader"
  ),
  "repair_protocol": RustTypeInfo(
    type_name = "RepairProtocol",
    dep_str   = "solana_core::repair::serve_repair::RepairProtocol"
  ),
  "duplicate_slot_proof": RustTypeInfo(
    type_name = "DuplicateSlotProof",
    dep_str   = "solana_ledger::blockstore_meta::DuplicateSlotProof"
  ),
}

# The following dependencies are always included in the generated file
standard_deps = [
  "std::collections::HashMap",
  "crate::types::types_processor::process_type",
  "crate::proto::TypeEffects",
]

def emit_dep( dep: str ) -> str:
    return f"use {dep};"

def emit_type_processor_map_insert( idx: int, type: str, map_name: str )-> str:
    return f"{map_name}.insert({idx}, process_type::<{type}>);"

def init_fd_types_index_map( type_names_source: str ):
    fd_types_index_map = {}
    counter = 0
    lines = type_names_source.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            continue
        if ".name=" in line:
            type_name = line.split(".name=\"")[1].split("\"")[0].strip().strip("\"")
            fd_types_index_map[type_name] = counter
            counter += 1
    return fd_types_index_map


def main():
    parser = argparse.ArgumentParser(description='Generate types map for types harness')
    parser.add_argument('fd_types_json', help='Path to fd_types.json file')
    parser.add_argument('fd_types_reflect', help='Path to fd_types_reflect_generated.c file')
    parser.add_argument('out', help='Output path for file (e.g. src/types/types_generated.rs)')
    parser.add_argument('--print-whitelist-idx', action='store_true', help='Print the whitelist of types indices to stdout (to apply to solfuzz mutator)')
    args = parser.parse_args()

    with open(args.fd_types_json, 'r') as fd_types_file:
        types_dict = json.load(fd_types_file)["entries"]

    with open(args.fd_types_reflect, 'r') as fd_types_reflect_file:
        types_idx = init_fd_types_index_map(fd_types_reflect_file.read())

    to_print = [
        (
            emit_dep(fd_rust_types_map[entry["name"]].dep_str),
            emit_type_processor_map_insert(
                types_idx[f'fd_{entry["name"]}'],
                fd_rust_types_map[entry["name"]].type_name,
                "map"
            )
        ) for entry in types_dict
        if entry["name"] in fd_rust_types_map
    ]
    type_deps = ""
    map_inserts = ""
    for dep, insert in to_print:
        type_deps += f"{dep}\n"
        map_inserts += f"    {insert}\n"

    # Sort the dependencies (to make rustfmt happy)
    type_deps = "\n".join(sorted(type_deps.splitlines()))

    # Emit the Rust code
    with open(args.out, 'w') as out:
        print("// This file is auto-generated by scripts/generate_types_map.py", file=out)
        print("// Do not edit this file directly.", file=out)

        # Emit dependencies
        standard_deps.sort()
        for dep in standard_deps:
            print(emit_dep(dep), file=out)
        print("", file=out)
        print("// Type imports", file=out)
        print(type_deps, file=out)

        print("type TypeProcessorFn = fn(&[u8]) -> Option<TypeEffects>;", file=out)

        print(
"""
fn build_type_processor_map() -> HashMap<u8, TypeProcessorFn> {
    let mut map: HashMap<u8, TypeProcessorFn> = HashMap::new();
""", file=out)

        print(map_inserts, file=out)
        print("    map", file=out)
        print("}", file=out)

        print(
"""
use std::sync::LazyLock;
pub static TYPE_PROCESSORS: LazyLock<HashMap<u8, TypeProcessorFn>> =
    LazyLock::new(build_type_processor_map);""", file=out)

    if args.print_whitelist_idx:
        print("Whitelist indices:")
        for entry in types_dict:
            if entry["name"] in fd_rust_types_map:
                print(str(types_idx[f'fd_{entry["name"]}']) + ',')
        print("Done printing whitelist indices")

if __name__ == "__main__":
    main()
