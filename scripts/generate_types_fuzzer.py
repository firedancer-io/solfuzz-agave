import sys
import json

# unknown agave counterpart, names dont match 1:1
# TODO: manually add them to the mapping
blacklist = [
    "pubkey", # this is a macro in FD to fd_hash_t
    "gossip_ip4_addr",
    "gossip_ip6_addr",
    "hash_hash_age_pair",
    "block_hash_vec",
    "block_hash_queue",
    "slot_pair",
    "solana_account",
    "solana_account_stored_meta",
    "solana_account_meta",
    "solana_account_hdr",
    "account_meta",
    "vote_accounts_pair",
    "account_keys_pair",
    "stake_weight",
    "stake_weights",
    "delegation",
    "delegation_pair",
    "stake",
    "stake_pair",
    "stakes_stake",
    "pubkey_node_vote_accounts_pair",
    "pubkey_pubkey_pair",
    "epoch_epoch_stakes_pair",
    "pubkey_u64_pair",
    "unused_accounts",
    "versioned_bank",
    "bank_hash_info",
    "slot_map_pair",
    "snapshot_acc_vec",
    "snapshot_slot_acc_vecs",
    "reward_type",
    "solana_accounts_db_fields",
    "versioned_epoch_stakes_current",
    "versioned_epoch_stakes_pair",
    "reward_info",
    "slot_lthash",
    "solana_manifest",
    "rust_duration",
    "string_pubkey_pair",
    "pubkey_account_pair",
    "genesis_solana",
    "vote_lockout",
    "lockout_offset",
    "vote_authorized_voter",
    "vote_prior_voter",
    "vote_prior_voter_0_23_5",
    "vote_epoch_credits",
    "vote_block_timestamp",
    "vote_prior_voters",
    "vote_prior_voters_0_23_5",
    "landed_vote",
    "vote_state_0_23_5",
    "vote_authorized_voters",
    "vote_state_1_14_11",
    "vote_state",
    "vote_state_versioned",
    "vote_state_update",
    "compact_vote_state_update",
    "compact_vote_state_update_switch",
    "compact_tower_sync",
    "tower_sync",
    "tower_sync_switch",
    "slot_history_inner",
    "slot_history_bitvec",
    "slot_history",
    "slot_hash",
    "slot_hashes",
    "block_block_hash_entry",
    "recent_block_hashes",
    "slot_meta",
    "clock_timestamp_vote",
    "clock_timestamp_votes",
    "config_keys_pair",
    "stake_config",
    "feature_entry",
    "firedancer_bank",
    "cluster_type",
    "rent_fresh_account",
    "rent_fresh_accounts",
    "epoch_bank",
    "slot_bank",
    "prev_epoch_inflation_rewards",
    "vote",
    "vote_init",
    "vote_authorize",
    "vote_authorize_pubkey",
    "vote_switch",
    "update_vote_state_switch",
    "vote_authorize_with_seed_args",
    "vote_authorize_checked_with_seed_args",
    "vote_instruction",
    "system_program_instruction_create_account",
    "system_program_instruction_create_account_with_seed",
    "system_program_instruction_allocate_with_seed",
    "system_program_instruction_assign_with_seed",
    "system_program_instruction_transfer_with_seed",
    "system_program_instruction",
    "system_error",
    "stake_authorized",
    "stake_lockup",
    "stake_instruction_initialize",
    "stake_lockup_custodian_args",
    "stake_authorize",
    "stake_instruction_authorize",
    "authorize_with_seed_args",
    "authorize_checked_with_seed_args",
    "lockup_checked_args",
    "lockup_args",
    "stake_instruction",
    "stake_meta",
    "stake_flags",
    "stake_state_v2_initialized",
    "stake_state_v2_stake",
    "stake_state_v2",
    "nonce_data",
    "nonce_state",
    "nonce_state_versions",
    "compute_budget_program_instruction_request_units_deprecated",
    "compute_budget_program_instruction",
    "bpf_loader_program_instruction_write",
    "bpf_loader_program_instruction",
    "loader_v4_program_instruction_write",
    "loader_v4_program_instruction_truncate",
    "loader_v4_program_instruction",
    "bpf_upgradeable_loader_program_instruction_write",
    "bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len",
    "bpf_upgradeable_loader_program_instruction_extend_program",
    "bpf_upgradeable_loader_program_instruction",
    "bpf_upgradeable_loader_state_buffer",
    "bpf_upgradeable_loader_state_program",
    "bpf_upgradeable_loader_state_program_data",
    "bpf_upgradeable_loader_state",
    "loader_v4_state",
    "lookup_table_meta",
    "address_lookup_table",
    "address_lookup_table_state",
    "gossip_bitvec_u8_inner",
    "gossip_bitvec_u8",
    "gossip_bitvec_u64_inner",
    "gossip_bitvec_u64",
    "gossip_ping",
    "gossip_ip_addr",
    "gossip_prune_data",
    "gossip_prune_sign_data",
    "gossip_prune_sign_data_with_prefix",
    "gossip_socket_addr_old",
    "gossip_socket_addr_ip4",
    "gossip_socket_addr_ip6",
    "gossip_socket_addr",
    "gossip_contact_info_v1",
    "gossip_vote",
    "gossip_lowest_slot",
    "gossip_slot_hashes",
    "gossip_slots",
    "gossip_flate2_slots",
    "gossip_slots_enum",
    "gossip_epoch_slots",
    "gossip_version_v1",
    "gossip_version_v2",
    "gossip_version_v3",
    "gossip_node_instance",
    "gossip_duplicate_shred",
    "gossip_incremental_snapshot_hashes",
    "gossip_socket_entry",
    "gossip_contact_info_v2",
    "restart_run_length_encoding_inner",
    "restart_run_length_encoding",
    "restart_raw_offsets_bitvec_u8_inner",
    "restart_raw_offsets_bitvec",
    "restart_raw_offsets",
    "restart_slots_offsets",
    "gossip_restart_last_voted_fork_slots",
    "gossip_restart_heaviest_fork",
    "crds_bloom",
    "gossip_pull_req",
    "gossip_pull_resp",
    "gossip_push_msg",
    "gossip_prune_msg",
    "gossip_msg",
    "addrlut_create",
    "addrlut_extend",
    "addrlut_instruction",
    "repair_window_index",
    "repair_highest_window_index",
    "repair_orphan",
    "repair_ancestor_hashes",
    "repair_response",
    "instr_error_enum",
    "txn_instr_error",
    "txn_error_enum",
    "cache_status",
    "status_value",
    "status_pair",
    "bank_slot_deltas",
    "pubkey_rewardinfo_pair",
    "optional_account",
    "calculated_stake_points",
    "calculated_stake_rewards",
    "epoch_info_pair",
    "vote_info_pair",
    "account_costs_pair",
    "account_costs",
    "stakes",
    "slot_delta",
    "usage_cost_details",
    "transaction_cost",
    "account_keys",
    "txn_result",
    "cost_tracker",
    "epoch_info", # same name different type

    # known mismatches
    # "stake_history_entry",
    # "repair_request_header",
    # "duplicate_slot_proof", # uchar instead of vec<uchar> in walk()
    # "epoch_stakes", # OOM in agave
    # "crds_value",
    # "crds_data",
    # "config_keys",
    # "versioned_epoch_stakes", # OOM in agave
    # "crds_filter",
]

# map fd type names to agave names
mapping = {
    "hash_age": "HashInfo",
    "sol_sysvar_clock": "Clock",
    "sol_sysvar_last_restart_slot": "LastRestartSlot",
    "sysvar_fees": "Fees",
    "sysvar_epoch_rewards": "EpochRewards",
}

dependencies = [
    "bincode",
    "serde::Serialize",
    "solana_accounts_db::blockhash_queue::HashInfo",
    "solana_clock::Clock",
    "solana_config_program::ConfigKeys",
    "solana_core::repair::serve_repair::RepairProtocol",
    "solana_epoch_rewards::EpochRewards",
    "solana_fee_calculator::FeeCalculator",
    "solana_fee_calculator::FeeRateGovernor",
    "solana_hard_forks::HardForks",
    "solana_hash::Hash",
    "solana_inflation::Inflation",
    "solana_last_restart_slot::LastRestartSlot",
    "solana_ledger::blockstore_meta::FrozenHashStatus",
    "solana_ledger::blockstore_meta::FrozenHashVersioned",
    "solana_poh_config::PohConfig",
    "solana_program::sysvar::epoch_schedule::EpochSchedule",
    "solana_program::sysvar::fees::Fees",
    "solana_program::sysvar::rent::Rent",
    "solana_program::sysvar::stake_history::StakeHistory",
    "solana_program::sysvar::stake_history::StakeHistoryEntry",
    "solana_rent_collector::RentCollector",
    "solana_runtime::bank::BankHashStats",
    "solana_runtime::epoch_stakes::NodeVoteAccounts",
    "solana_runtime::serde_snapshot::BankIncrementalSnapshotPersistence",
    "solana_sdk::feature::Feature",
    "solana_sdk::signature::Signature",
    "solana_vote::vote_account::VoteAccounts",
    "solana_runtime::epoch_stakes::EpochStakes",
    "solana_runtime::epoch_stakes::VersionedEpochStakes",
    "solana_gossip::crds_data::CrdsData",
    "solana_gossip::crds_gossip_pull::CrdsFilter",
    "solana_gossip::crds_value::CrdsValue",
    "solana_core::repair::serve_repair::RepairRequestHeader",
    "solana_ledger::blockstore_meta::DuplicateSlotProof",
    "std::ffi::c_int",
]

def snake_to_camel(snake_str):
    components = snake_str.split('_')
    return ''.join(x.title() for x in components)

def find_line_number(content, search_string):
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_string in line:
            return i-4
    return -1

def main():
    if len(sys.argv) < 3:
        print(f'Usage: python3 {sys.argv[0]} <fd_types.json> <fd_type_names.c> <types_fuzzer.rs>')
        sys.exit(0)

    with open(sys.argv[1], 'r') as json_file:
        json_object = json.load(json_file)
        types_dict = json_object['entries']

        # necessary because fd_type_names indexing is different from fd_types.json
        type_names = open(sys.argv[2], "r").read()
        body = open(sys.argv[3], "w")

        print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)
        for dependency in dependencies:
            print(f"use {dependency};", file=body)
        print("", file=body)

        print("#[no_mangle]", file=body)
        print("pub unsafe extern \"C\" fn sol_compat_type_execute_v1(", file=body)
        print("    out_ptr: *mut u8,", file=body)
        print("    out_psz: *mut u64,", file=body)
        print("    in_bincode_ptr: *mut u8,", file=body)
        print("    in_bincode_sz: u64,", file=body)
        print(") -> c_int {", file=body)
        print("    if in_bincode_sz == 0 {", file=body)
        print("        return 0;", file=body)
        print("    }\n", file=body)
        print("    let bincode_slice: &[u8] = unsafe {", file=body)
        print("        std::slice::from_raw_parts(in_bincode_ptr, in_bincode_sz as usize)", file=body)
        print("    };\n", file=body)
        print("    match bincode_slice[0] {", file=body)

        for entry in types_dict:
            name = snake_to_camel(entry['name'])
            
            if entry['name'] in mapping:
                name = mapping[entry['name']]

            if entry['name'] not in blacklist:
                # map to the correct index
                idx = find_line_number(type_names, '"fd_' + entry['name'] + '"')
                if idx != -1:
                    print(f"        {idx} => {{", file=body)
                    print(f"            let typ: {name} = if let Ok(h) = bincode::deserialize(&bincode_slice[1..]) {{", file=body)
                    print("                h", file=body)
                    print("            } else {", file=body)
                    print("                return 0;", file=body)
                    print("            };\n", file=body)
                    print("            let mut ser = super::CustomSerializer::new();", file=body)
                    print("            typ.serialize(&mut ser).unwrap();", file=body)
                    print("            let ser_sz = ser.output.len();", file=body)
                    print("            let yaml_str = serde_yaml::to_string(&typ).unwrap();", file=body)
                    print("            let yaml_sz = yaml_str.len();", file=body)
                    print("            unsafe {", file=body)
                    print("                *out_psz = (std::mem::size_of::<u64>() + ser_sz + yaml_sz) as u64;", file=body)
                    print("                std::ptr::copy_nonoverlapping(&ser_sz as *const usize as *const u64, out_ptr as *mut u64, std::mem::size_of::<u64>());", file=body)
                    print("                std::ptr::copy_nonoverlapping(ser.output.as_ptr(), out_ptr.offset(std::mem::size_of::<u64>() as isize), ser_sz as usize);", file=body)
                    print("                std::ptr::copy_nonoverlapping(yaml_str.as_ptr(), out_ptr.offset((std::mem::size_of::<u64>() + ser_sz) as isize), yaml_sz as usize);", file=body)
                    print("            }", file=body)
                    print("        }", file=body)
                else:
                    print(f'not found {entry["name"]} in {sys.argv[2]}')

        print("        _ => return 0,", file=body)
        print("    };", file=body)
        print("    1", file=body)
        print("}", file=body)

if __name__ == "__main__":
    main()
