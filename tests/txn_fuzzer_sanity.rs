// use prost::Message;
// use solana_program::bpf_loader_upgradeable;
// use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState;
// use solana_program::hash::Hash;
// use solana_program::pubkey::Pubkey;
// use solana_sdk::clock::Clock;
// use solana_sdk::epoch_schedule::EpochSchedule;
// use solana_sdk::rent::Rent;
// use solana_sdk::signature::Signature;
// use solana_sdk::sysvar::SysvarId;
// use solana_sdk::{address_lookup_table, feature_set::*};
// use solfuzz_agave::proto::{
//     AcctState, CompiledInstruction, EpochContext, FeatureSet, MessageHeader, SanitizedTransaction,
//     SlotContext, TransactionMessage, TxnContext, TxnResult,
// };
// use solfuzz_agave::txn_fuzzer::sol_compat_txn_execute_v1;
// use solfuzz_agave::{feature_list, proto, utils::feature_u64, HARDCODED_FEATURES};
// use std::fs::File;
// use std::io::{Read, Write};
// use std::{env, fs};

// #[allow(unused)]
// fn write_to_file(filename: &str, buffer: &[u8]) {
//     let mut dir = env::current_dir().unwrap();
//     dir.push("tests");
//     dir.push(filename);
//     dir.set_extension("bin");

//     let mut file = File::create(dir).unwrap();
//     file.write_all(buffer).expect("Failed to write to file");
// }

// fn get_features() -> FeatureSet {
//     // Add any other features that should be appended to the hardcoded features list
//     let additional_features = feature_list![set_exempt_rent_epoch_max];
//     let mut features = FeatureSet::default();

//     features.features = HARDCODED_FEATURES.into();
//     features.features.extend_from_slice(additional_features);
//     features
// }

// fn get_clock_sysvar_account() -> AcctState {
//     let clock = Clock {
//         slot: 20,
//         epoch_start_timestamp: 1720556855,
//         epoch: 0,
//         leader_schedule_epoch: 1,
//         unix_timestamp: 1720556855,
//     };
//     AcctState {
//         address: Clock::id().to_bytes().to_vec(),
//         lamports: 1,
//         data: bincode::serialize(&clock).unwrap(),
//         executable: false,
//         rent_epoch: u64::MAX,
//         owner: solana_sdk::native_loader::id().to_bytes().to_vec(),
//         seed_addr: None,
//     }
// }

// fn get_epoch_schedule_sysvar_account() -> AcctState {
//     let epoch_schedule = EpochSchedule {
//         slots_per_epoch: 432000,
//         leader_schedule_slot_offset: 432000,
//         warmup: true,
//         first_normal_epoch: 14,
//         first_normal_slot: 524256,
//     };
//     AcctState {
//         address: EpochSchedule::id().to_bytes().to_vec(),
//         lamports: 1,
//         data: bincode::serialize(&epoch_schedule).unwrap(),
//         executable: false,
//         rent_epoch: u64::MAX,
//         owner: solana_sdk::native_loader::id().to_bytes().to_vec(),
//         seed_addr: None,
//     }
// }

// fn get_rent_sysvar_account() -> AcctState {
//     let rent = solana_sdk::rent::Rent {
//         lamports_per_byte_year: 3480,
//         exemption_threshold: 2.0,
//         burn_percent: 50,
//     };
//     AcctState {
//         address: Rent::id().to_bytes().to_vec(),
//         lamports: 1,
//         data: bincode::serialize(&rent).unwrap(),
//         executable: false,
//         rent_epoch: u64::MAX,
//         owner: solana_sdk::native_loader::id().to_bytes().to_vec(),
//         seed_addr: None,
//     }
// }

// fn load_program(name: String) -> Vec<u8> {
//     // Loading the program file
//     let mut dir = env::current_dir().unwrap();
//     dir.push("tests");
//     let name = name.replace('-', "_");
//     dir.push(name + "_program.so");
//     let mut file = File::open(dir.clone()).expect("file not found");
//     let metadata = fs::metadata(dir).expect("Unable to read metadata");
//     let mut buffer = vec![0; metadata.len() as usize];
//     file.read_exact(&mut buffer).expect("Buffer overflow");
//     buffer
// }

// fn deploy_program(name: String) -> [(Pubkey, AcctState); 2] {
//     let program_account = Pubkey::new_unique();
//     let program_data_account = Pubkey::new_unique();
//     let state = UpgradeableLoaderState::Program {
//         programdata_address: program_data_account,
//     };

//     // The program account must have funds and hold the executable binary
//     let program_account_state = AcctState {
//         address: program_account.to_bytes().to_vec(),
//         lamports: 25,
//         data: bincode::serialize(&state).unwrap(),
//         executable: true,
//         rent_epoch: 0,
//         owner: bpf_loader_upgradeable::id().to_bytes().to_vec(),
//         seed_addr: None,
//     };

//     let state = UpgradeableLoaderState::ProgramData {
//         slot: 0,
//         upgrade_authority_address: None,
//     };
//     let mut header = bincode::serialize(&state).unwrap();
//     let mut complement = vec![
//         0;
//         std::cmp::max(
//             0,
//             UpgradeableLoaderState::size_of_programdata_metadata().saturating_sub(header.len())
//         )
//     ];
//     let mut buffer = load_program(name);
//     header.append(&mut complement);
//     header.append(&mut buffer);

//     let program_data_account_state = AcctState {
//         address: program_data_account.to_bytes().to_vec(),
//         lamports: 25,
//         data: header,
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     [
//         (program_account, program_account_state),
//         (program_data_account, program_data_account_state),
//     ]
// }

// #[test]
// fn test_txn_execute_clock() {
//     let clock_sysvar = get_clock_sysvar_account();
//     let epoch_schedule = get_epoch_schedule_sysvar_account();
//     let rent = get_rent_sysvar_account();

//     let slot_ctx = SlotContext { slot: 20 };
//     let features = get_features();
//     let epoch_ctx = EpochContext {
//         features: Some(features),
//     };

//     let header = MessageHeader {
//         num_required_signatures: 1,
//         num_readonly_signed_accounts: 0,
//         num_readonly_unsigned_accounts: 0,
//     };

//     let fee_payer = Pubkey::new_unique();
//     let fee_payer_data = AcctState {
//         address: fee_payer.to_bytes().to_vec(),
//         lamports: 80000000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let mut program_info = deploy_program("clock-sysvar".to_string());

//     let p_acc = std::mem::take(&mut program_info[0].1);
//     let pd_acc = std::mem::take(&mut program_info[1].1);

//     let instr = CompiledInstruction {
//         program_id_index: 1,
//         accounts: vec![],
//         data: vec![],
//     };

//     let blockhash_queue = vec![
//         Hash::new_unique().to_bytes().to_vec(),
//         Hash::new_unique().to_bytes().to_vec(),
//     ];

//     let message = TransactionMessage {
//         is_legacy: true,
//         header: Some(header),
//         account_keys: vec![
//             fee_payer.to_bytes().to_vec(),
//             program_info[0].0.to_bytes().to_vec(),
//         ],
//         recent_blockhash: blockhash_queue[1].clone(),
//         account_shared_data: vec![
//             fee_payer_data,
//             p_acc,
//             pd_acc,
//             clock_sysvar,
//             epoch_schedule,
//             rent,
//         ],
//         instructions: vec![instr],
//         address_table_lookups: vec![],
//     };

//     let tx = SanitizedTransaction {
//         message: Some(message),
//         message_hash: Hash::new_unique().to_bytes().to_vec(),
//         is_simple_vote_tx: false,
//         signatures: vec![Signature::new_unique().as_ref().to_vec()],
//     };

//     let txn_input = TxnContext {
//         tx: Some(tx),
//         max_age: 500,
//         blockhash_queue: blockhash_queue,
//         epoch_ctx: Some(epoch_ctx),
//         slot_ctx: Some(slot_ctx),
//     };

//     let mut buffer: Vec<u8> = txn_input.encode_to_vec();
//     let buffer_len = buffer.len() as u64;

//     // Uncomment to write the data to a file
//     // write_to_file("clock-test", &buffer);

//     let mut res_buffer: Vec<u8> = vec![0; 512];
//     let mut res_buffer_len = res_buffer.len() as u64;
//     let res = unsafe {
//         sol_compat_txn_execute_v1(
//             res_buffer.as_mut_ptr(),
//             &mut res_buffer_len,
//             buffer.as_mut_ptr(),
//             buffer_len,
//         )
//     };

//     assert_eq!(res, 1);
//     let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
//     assert!(result.executed);
//     assert!(result.is_ok);
//     assert_eq!(result.return_data.len(), 8);
// }

// #[test]
// fn test_simple_transfer() {
//     let clock_sysvar = get_clock_sysvar_account();
//     let epoch_schedule = get_epoch_schedule_sysvar_account();
//     let rent = get_rent_sysvar_account();

//     let slot_ctx = SlotContext { slot: 20 };
//     let features = get_features();
//     let epoch_ctx = EpochContext {
//         features: Some(features),
//     };

//     let header = MessageHeader {
//         num_required_signatures: 2,
//         num_readonly_signed_accounts: 0,
//         num_readonly_unsigned_accounts: 1,
//     };

//     let fee_payer = Pubkey::new_unique();
//     let fee_payer_data = AcctState {
//         address: fee_payer.to_bytes().to_vec(),
//         lamports: 10000000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let sender = Pubkey::new_unique();
//     let sender_data = AcctState {
//         address: sender.to_bytes().to_vec(),
//         lamports: 900000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let recipient = Pubkey::new_unique();
//     let recipient_data = AcctState {
//         address: recipient.to_bytes().to_vec(),
//         lamports: 900000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let mut program_info = deploy_program("simple-transfer".to_string());

//     let p_acc = std::mem::take(&mut program_info[0].1);
//     let pd_acc = std::mem::take(&mut program_info[1].1);

//     let instr = CompiledInstruction {
//         program_id_index: 3,
//         accounts: vec![1, 2, 4],
//         data: vec![0, 0, 0, 0, 0, 0, 0, 10],
//     };

//     let blockhash_queue = vec![
//         Hash::new_unique().to_bytes().to_vec(),
//         Hash::new_unique().to_bytes().to_vec(),
//     ];

//     let message = TransactionMessage {
//         is_legacy: false,
//         header: Some(header),
//         account_keys: vec![
//             fee_payer.to_bytes().to_vec(),
//             sender.to_bytes().to_vec(),
//             recipient.to_bytes().to_vec(),
//             program_info[0].0.to_bytes().to_vec(),
//             vec![0; 32],
//         ],
//         account_shared_data: vec![
//             fee_payer_data,
//             recipient_data,
//             sender_data,
//             p_acc,
//             pd_acc,
//             clock_sysvar,
//             epoch_schedule,
//             rent,
//         ],
//         instructions: vec![instr],
//         address_table_lookups: vec![],
//         recent_blockhash: blockhash_queue[1].clone(),
//     };

//     let tx = SanitizedTransaction {
//         message: Some(message),
//         message_hash: Hash::new_unique().to_bytes().to_vec(),
//         is_simple_vote_tx: false,
//         signatures: vec![
//             Signature::new_unique().as_ref().to_vec(),
//             Signature::new_unique().as_ref().to_vec(),
//         ],
//     };

//     let txn_input = TxnContext {
//         tx: Some(tx),
//         max_age: 500,
//         blockhash_queue: blockhash_queue,
//         epoch_ctx: Some(epoch_ctx),
//         slot_ctx: Some(slot_ctx),
//     };

//     let mut buffer: Vec<u8> = txn_input.encode_to_vec();
//     let buffer_len = buffer.len() as u64;

//     // Uncomment to write the data to a file
//     // write_to_file("simple-transfer", &buffer);

//     let mut res_buffer: Vec<u8> = vec![0; 68007];
//     let mut res_buffer_len = res_buffer.len() as u64;
//     let res = unsafe {
//         sol_compat_txn_execute_v1(
//             res_buffer.as_mut_ptr(),
//             &mut res_buffer_len,
//             buffer.as_mut_ptr(),
//             buffer_len,
//         )
//     };

//     assert_eq!(res, 1);
//     let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
//     assert!(result.executed);
//     assert!(result.is_ok);
//     if let Some(state) = &result.resulting_state {
//         for item in &state.acct_states {
//             if item.address.eq(&sender.to_bytes()) {
//                 assert_eq!(item.lamports, 899990);
//             } else if item.address.eq(&recipient.to_bytes()) {
//                 assert_eq!(item.lamports, 900010);
//             }
//         }
//     }
// }

// #[test]
// fn test_lookup_table() {
//     let clock_sysvar = get_clock_sysvar_account();
//     let epoch_schedule = get_epoch_schedule_sysvar_account();
//     let rent = get_rent_sysvar_account();

//     let slot_ctx = SlotContext { slot: 20 };
//     let features = get_features();
//     let epoch_ctx = EpochContext {
//         features: Some(features),
//     };

//     let header = MessageHeader {
//         num_required_signatures: 2,
//         num_readonly_signed_accounts: 0,
//         num_readonly_unsigned_accounts: 2,
//     };

//     let fee_payer = Pubkey::new_unique();
//     let fee_payer_data = AcctState {
//         address: fee_payer.to_bytes().to_vec(),
//         lamports: 10000000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let sender = Pubkey::new_unique();
//     let sender_data = AcctState {
//         address: sender.to_bytes().to_vec(),
//         lamports: 900000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let recipient = Pubkey::new_unique();
//     let recipient_data = AcctState {
//         address: recipient.to_bytes().to_vec(),
//         lamports: 900000,
//         data: vec![],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let extra_account = Pubkey::new_unique();
//     let extra_data = AcctState {
//         address: extra_account.to_bytes().to_vec(),
//         lamports: 2,
//         data: vec![5, 0, 0, 0, 0, 0, 0, 0],
//         executable: false,
//         rent_epoch: 0,
//         owner: vec![0; 32],
//         seed_addr: None,
//     };

//     let mut program_info = deploy_program("complex-transfer".to_string());

//     let p_acc = std::mem::take(&mut program_info[0].1);
//     let pd_acc = std::mem::take(&mut program_info[1].1);

//     let instr = CompiledInstruction {
//         program_id_index: 2,
//         accounts: vec![1, 4, 3, 5],
//         data: vec![0, 0, 0, 0, 0, 0, 0, 10],
//     };

//     let table_lookup = proto::MessageAddressTableLookup {
//         account_key: vec![1; 32],
//         writable_indexes: vec![0],
//         readonly_indexes: vec![1],
//     };

//     // Fill ALUT account data (first 56 bytes dont matter except discriminant)
//     let mut alut_data = vec![1];
//     for _ in 0..55 {
//         alut_data.push(0);
//     }
//     alut_data.extend_from_slice(&recipient.to_bytes());
//     alut_data.extend_from_slice(&extra_account.to_bytes());

//     let address_lookup_table_acc = AcctState {
//         address: vec![1; 32],
//         lamports: 1,
//         data: alut_data,
//         executable: false,
//         rent_epoch: 0,
//         owner: address_lookup_table::program::id().to_bytes().to_vec(),
//         seed_addr: None,
//     };

//     let blockhash_queue = vec![
//         Hash::new_unique().to_bytes().to_vec(),
//         Hash::new_unique().to_bytes().to_vec(),
//     ];

//     let message = TransactionMessage {
//         is_legacy: false,
//         header: Some(header),
//         account_keys: vec![
//             fee_payer.to_bytes().to_vec(),
//             sender.to_bytes().to_vec(),
//             program_info[0].0.to_bytes().to_vec(),
//             vec![0; 32],
//         ],
//         account_shared_data: vec![
//             fee_payer_data,
//             recipient_data,
//             sender_data,
//             p_acc,
//             pd_acc,
//             extra_data,
//             address_lookup_table_acc,
//             clock_sysvar,
//             epoch_schedule,
//             rent,
//         ],
//         instructions: vec![instr],
//         address_table_lookups: vec![table_lookup],
//         recent_blockhash: blockhash_queue[1].clone(),
//     };

//     let tx = SanitizedTransaction {
//         message: Some(message),
//         message_hash: Hash::new_unique().to_bytes().to_vec(),
//         is_simple_vote_tx: false,
//         signatures: vec![
//             Signature::new_unique().as_ref().to_vec(),
//             Signature::new_unique().as_ref().to_vec(),
//         ],
//     };

//     let txn_input = TxnContext {
//         tx: Some(tx),
//         max_age: 500,
//         blockhash_queue: blockhash_queue,
//         epoch_ctx: Some(epoch_ctx),
//         slot_ctx: Some(slot_ctx),
//     };

//     let mut buffer: Vec<u8> = txn_input.encode_to_vec();
//     let buffer_len = buffer.len() as u64;

//     // Uncomment to write the data to a file
//     // write_to_file("lookup-table", &buffer);

//     let mut res_buffer: Vec<u8> = vec![0; 120761];
//     let mut res_buffer_len = res_buffer.len() as u64;
//     let res = unsafe {
//         sol_compat_txn_execute_v1(
//             res_buffer.as_mut_ptr(),
//             &mut res_buffer_len,
//             buffer.as_mut_ptr(),
//             buffer_len,
//         )
//     };

//     assert_eq!(res, 1);
//     let result = TxnResult::decode(&res_buffer[..res_buffer_len as usize]).unwrap();
//     assert!(result.executed);
//     assert!(result.is_ok);
//     if let Some(state) = &result.resulting_state {
//         for item in &state.acct_states {
//             if item.address.eq(&sender.to_bytes()) {
//                 assert_eq!(item.lamports, 899985);
//             } else if item.address.eq(&recipient.to_bytes()) {
//                 assert_eq!(item.lamports, 900015);
//             }
//         }
//     }
// }
