use prost::Message;
use solana_program::bpf_loader_upgradeable;
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState;
use solana_program::hash::Hash;
use solana_program::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solfuzz_agave::proto;
use solfuzz_agave::proto::{
    AcctState, CompiledInstruction, EpochContext, MessageHeader, SanitizedTransaction, SlotContext,
    TransactionMessage, TxnContext, TxnResult,
};
use solfuzz_agave::txn_fuzzer::sol_compat_txn_execute_v1;
use std::fs::File;
use std::io::{Read, Write};
use std::{env, fs};

#[allow(unused)]
fn write_to_file(filename: &str, buffer: &[u8]) {
    let mut dir = env::current_dir().unwrap();
    dir.push("tests");
    dir.push(filename);
    dir.set_extension("bin");

    let mut file = File::create(dir).unwrap();
    file.write_all(buffer).expect("Failed to write to file");
}

fn load_program(name: String) -> Vec<u8> {
    // Loading the program file
    let mut dir = env::current_dir().unwrap();
    dir.push("tests");
    let name = name.replace('-', "_");
    dir.push(name + "_program.so");
    let mut file = File::open(dir.clone()).expect("file not found");
    let metadata = fs::metadata(dir).expect("Unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    file.read_exact(&mut buffer).expect("Buffer overflow");
    buffer
}

fn deploy_program(name: String) -> [(Pubkey, AcctState); 2] {
    let program_account = Pubkey::new_unique();
    let program_data_account = Pubkey::new_unique();
    let state = UpgradeableLoaderState::Program {
        programdata_address: program_data_account,
    };

    // The program account must have funds and hold the executable binary
    let program_account_state = AcctState {
        address: program_account.to_bytes().to_vec(),
        lamports: 25,
        data: bincode::serialize(&state).unwrap(),
        executable: false,
        rent_epoch: 0,
        owner: bpf_loader_upgradeable::id().to_bytes().to_vec(),
        seed_addr: None,
    };

    let state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: None,
    };
    let mut header = bincode::serialize(&state).unwrap();
    let mut complement = vec![
        0;
        std::cmp::max(
            0,
            UpgradeableLoaderState::size_of_programdata_metadata().saturating_sub(header.len())
        )
    ];
    let mut buffer = load_program(name);
    header.append(&mut complement);
    header.append(&mut buffer);

    let program_data_account_state = AcctState {
        address: program_data_account.to_bytes().to_vec(),
        lamports: 25,
        data: header,
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    [
        (program_account, program_account_state),
        (program_data_account, program_data_account_state),
    ]
}

#[test]
fn test_txn_execute_clock() {
    let slot_ctx = SlotContext { slot: 20 };

    let epoch_ctx = EpochContext { features: None };

    let header = MessageHeader {
        num_required_signatures: 1,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 0,
    };

    let fee_payer = Pubkey::new_unique();
    let fee_payer_data = AcctState {
        address: fee_payer.to_bytes().to_vec(),
        lamports: 80000000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let mut program_info = deploy_program("clock-sysvar".to_string());

    let p_acc = std::mem::take(&mut program_info[0].1);
    let pd_acc = std::mem::take(&mut program_info[1].1);

    let instr = CompiledInstruction {
        program_id_index: 1,
        accounts: vec![],
        data: vec![],
    };

    let message = TransactionMessage {
        is_legacy: true,
        header: Some(header),
        account_keys: vec![
            fee_payer.to_bytes().to_vec(),
            program_info[0].0.to_bytes().to_vec(),
        ],
        recent_blockhash: Hash::new_unique().to_bytes().to_vec(),
        account_shared_data: vec![fee_payer_data, p_acc, pd_acc],
        instructions: vec![instr],
        address_table_lookups: vec![],
        loaded_addresses: None,
    };

    let tx = SanitizedTransaction {
        message: Some(message),
        message_hash: Hash::new_unique().to_bytes().to_vec(),
        is_simple_vote_tx: false,
        signatures: vec![Signature::new_unique().as_ref().to_vec()],
    };

    let txn_input = TxnContext {
        tx: Some(tx),
        max_age: 500,
        log_messages_byte_limit: 200,
        epoch_ctx: Some(epoch_ctx),
        slot_ctx: Some(slot_ctx),
        genesis_hash: Hash::new_unique().to_bytes().to_vec(),
    };

    let mut buffer: Vec<u8> = txn_input.encode_to_vec();
    let buffer_len = buffer.len() as u64;

    // Uncomment to write the data to a file
    //write_to_file("clock-test", &buffer);

    let mut res_buffer: Vec<u8> = vec![0; 512];
    let mut res_buffer_len = res_buffer.len() as u64;
    let res = unsafe {
        sol_compat_txn_execute_v1(
            res_buffer.as_mut_ptr(),
            &mut res_buffer_len,
            buffer.as_mut_ptr(),
            buffer_len,
        )
    };

    assert_eq!(res, 1);
    let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
    assert!(result.executed);
    assert!(result.is_ok);
    assert_eq!(result.return_data.len(), 8);
}

#[test]
fn test_simple_transfer() {
    let slot_ctx = SlotContext { slot: 20 };

    let epoch_ctx = EpochContext { features: None };

    let header = MessageHeader {
        num_required_signatures: 2,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 2,
    };

    let fee_payer = Pubkey::new_unique();
    let fee_payer_data = AcctState {
        address: fee_payer.to_bytes().to_vec(),
        lamports: 10000000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let sender = Pubkey::new_unique();
    let sender_data = AcctState {
        address: sender.to_bytes().to_vec(),
        lamports: 900000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let recipient = Pubkey::new_unique();
    let recipient_data = AcctState {
        address: recipient.to_bytes().to_vec(),
        lamports: 900000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let mut program_info = deploy_program("simple-transfer".to_string());

    let p_acc = std::mem::take(&mut program_info[0].1);
    let pd_acc = std::mem::take(&mut program_info[1].1);

    let instr = CompiledInstruction {
        program_id_index: 3,
        accounts: vec![1, 2, 5],
        data: vec![0, 0, 0, 0, 0, 0, 0, 10],
    };

    let message = TransactionMessage {
        is_legacy: false,
        header: Some(header),
        account_keys: vec![
            fee_payer.to_bytes().to_vec(),
            sender.to_bytes().to_vec(),
            recipient.to_bytes().to_vec(),
            program_info[0].0.to_bytes().to_vec(),
            program_info[1].0.to_bytes().to_vec(),
            vec![0; 32],
        ],
        account_shared_data: vec![fee_payer_data, recipient_data, sender_data, p_acc, pd_acc],
        instructions: vec![instr],
        address_table_lookups: vec![],
        loaded_addresses: None,
        recent_blockhash: Hash::new_unique().to_bytes().to_vec(),
    };

    let tx = SanitizedTransaction {
        message: Some(message),
        message_hash: Hash::new_unique().to_bytes().to_vec(),
        is_simple_vote_tx: false,
        signatures: vec![
            Signature::new_unique().as_ref().to_vec(),
            Signature::new_unique().as_ref().to_vec(),
        ],
    };

    let txn_input = TxnContext {
        tx: Some(tx),
        max_age: 500,
        log_messages_byte_limit: 200,
        epoch_ctx: Some(epoch_ctx),
        slot_ctx: Some(slot_ctx),
        genesis_hash: Hash::new_unique().to_bytes().to_vec(),
    };

    let mut buffer: Vec<u8> = txn_input.encode_to_vec();
    let buffer_len = buffer.len() as u64;

    // Uncomment to write the data to a file
    // write_to_file("simple-transfer", &buffer);

    let mut res_buffer: Vec<u8> = vec![0; 68007];
    let mut res_buffer_len = res_buffer.len() as u64;
    let res = unsafe {
        sol_compat_txn_execute_v1(
            res_buffer.as_mut_ptr(),
            &mut res_buffer_len,
            buffer.as_mut_ptr(),
            buffer_len,
        )
    };

    assert_eq!(res, 1);
    let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
    assert!(result.executed);
    assert!(result.is_ok);
    if let Some(state) = &result.resulting_state {
        for item in &state.acct_states {
            if item.address.eq(&sender.to_bytes()) {
                assert_eq!(item.lamports, 899990);
            } else if item.address.eq(&recipient.to_bytes()) {
                assert_eq!(item.lamports, 900010);
            }
        }
    }
}

#[test]
fn test_lookup_table() {
    let slot_ctx = SlotContext { slot: 20 };

    let epoch_ctx = EpochContext { features: None };

    let header = MessageHeader {
        num_required_signatures: 2,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 3,
    };

    let fee_payer = Pubkey::new_unique();
    let fee_payer_data = AcctState {
        address: fee_payer.to_bytes().to_vec(),
        lamports: 10000000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let sender = Pubkey::new_unique();
    let sender_data = AcctState {
        address: sender.to_bytes().to_vec(),
        lamports: 900000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let recipient = Pubkey::new_unique();
    let recipient_data = AcctState {
        address: recipient.to_bytes().to_vec(),
        lamports: 900000,
        data: vec![],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let extra_account = Pubkey::new_unique();
    let extra_data = AcctState {
        address: extra_account.to_bytes().to_vec(),
        lamports: 2,
        data: vec![5, 0, 0, 0, 0, 0, 0, 0],
        executable: false,
        rent_epoch: 0,
        owner: vec![0; 32],
        seed_addr: None,
    };

    let mut program_info = deploy_program("complex-transfer".to_string());

    let p_acc = std::mem::take(&mut program_info[0].1);
    let pd_acc = std::mem::take(&mut program_info[1].1);

    let instr = CompiledInstruction {
        program_id_index: 2,
        accounts: vec![1, 5, 4, 6],
        data: vec![0, 0, 0, 0, 0, 0, 0, 10],
    };

    let table_lookup = proto::MessageAddressTableLookup {
        account_key: vec![1; 32],
        writable_indexes: vec![1],
        readonly_indexes: vec![1],
    };

    let loaded_addresses = proto::LoadedAddresses {
        writable: vec![recipient.to_bytes().to_vec()],
        readonly: vec![extra_account.to_bytes().to_vec()],
    };

    let message = TransactionMessage {
        is_legacy: false,
        header: Some(header),
        account_keys: vec![
            fee_payer.to_bytes().to_vec(),
            sender.to_bytes().to_vec(),
            program_info[0].0.to_bytes().to_vec(),
            program_info[1].0.to_bytes().to_vec(),
            vec![0; 32],
        ],
        account_shared_data: vec![
            fee_payer_data,
            recipient_data,
            sender_data,
            p_acc,
            pd_acc,
            extra_data,
        ],
        instructions: vec![instr],
        address_table_lookups: vec![table_lookup],
        loaded_addresses: Some(loaded_addresses),
        recent_blockhash: Hash::new_unique().to_bytes().to_vec(),
    };

    let tx = SanitizedTransaction {
        message: Some(message),
        message_hash: Hash::new_unique().to_bytes().to_vec(),
        is_simple_vote_tx: false,
        signatures: vec![
            Signature::new_unique().as_ref().to_vec(),
            Signature::new_unique().as_ref().to_vec(),
        ],
    };

    let txn_input = TxnContext {
        tx: Some(tx),
        max_age: 500,
        log_messages_byte_limit: 200,
        epoch_ctx: Some(epoch_ctx),
        slot_ctx: Some(slot_ctx),
        genesis_hash: Hash::new_unique().to_bytes().to_vec(),
    };

    let mut buffer: Vec<u8> = txn_input.encode_to_vec();
    let buffer_len = buffer.len() as u64;

    // Uncomment to write the data to a file
    // write_to_file("lookup-table", &buffer);

    let mut res_buffer: Vec<u8> = vec![0; 120761];
    let mut res_buffer_len = res_buffer.len() as u64;
    let res = unsafe {
        sol_compat_txn_execute_v1(
            res_buffer.as_mut_ptr(),
            &mut res_buffer_len,
            buffer.as_mut_ptr(),
            buffer_len,
        )
    };

    assert_eq!(res, 1);
    let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
    assert!(result.executed);
    assert!(result.is_ok);
    if let Some(state) = &result.resulting_state {
        for item in &state.acct_states {
            if item.address.eq(&sender.to_bytes()) {
                assert_eq!(item.lamports, 899985);
            } else if item.address.eq(&recipient.to_bytes()) {
                assert_eq!(item.lamports, 900015);
            }
        }
    }
}
