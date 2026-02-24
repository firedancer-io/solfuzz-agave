use crate::proto;
use crate::proto::{AcctState, TxnContext, TxnResult};
use crate::utils::program::common::build_versioned_message;
use agave_feature_set::*;
use agave_precompiles::get_precompile;
use ahash::AHashSet;
use prost::Message;
use solana_account::{AccountSharedData, ReadableAccount};
use solana_accounts_db::accounts::Accounts;
use solana_accounts_db::accounts_db::{AccountsDb, AccountsDbConfig};
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_hash::AccountsLtHash;
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimitMb};
use solana_accounts_db::ancestors::AncestorsForSerialization;
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_clock::{Clock, Epoch, MAX_PROCESSING_AGE};
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_instruction::error::InstructionError;
use solana_lattice_hash::lt_hash::LtHash;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::v0::MessageAddressTableLookup;
use solana_message::MessageHeader;
use solana_message::SanitizedMessage;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_runtime::bank::{
    Bank, BankFieldsToDeserialize, BankHashStats, BankRc, LoadAndExecuteTransactionsOutput,
};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::epoch_stakes::VersionedEpochStakes;
use solana_runtime::rent_collector::RentCollector;
use solana_runtime::stakes::{SerdeStakesToStakeFormat, Stakes};
use solana_signature::Signature;
use solana_stake_interface::state::{Delegation, Stake};
use solana_svm::transaction_error_metrics::TransactionErrorMetrics;
use solana_svm::transaction_processing_result::{
    ProcessedTransaction, TransactionProcessingResultExtensions,
};
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionProcessingConfig};
use solana_svm_timings::ExecuteTimings;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::TransactionVerificationMode;
use solana_transaction_context::transaction_accounts::KeyedAccountSharedData;
use solana_transaction_error::TransactionError;
use std::cmp::max;
use std::collections::HashMap;
use std::ffi::c_int;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_txn_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let Ok(txn_context) = TxnContext::decode(&in_slice[..in_sz as usize]) else {
        return 0;
    };

    let Some(txn_result) = execute_transaction(&txn_context) else {
        return 0;
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = txn_result.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }

    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

impl From<&proto::MessageHeader> for MessageHeader {
    fn from(value: &proto::MessageHeader) -> Self {
        MessageHeader {
            num_required_signatures: max(1, value.num_required_signatures as u8),
            num_readonly_signed_accounts: value.num_readonly_signed_accounts as u8,
            num_readonly_unsigned_accounts: value.num_readonly_unsigned_accounts as u8,
        }
    }
}

impl From<&proto::CompiledInstruction> for CompiledInstruction {
    fn from(value: &proto::CompiledInstruction) -> Self {
        CompiledInstruction {
            program_id_index: value.program_id_index as u8,
            accounts: value.accounts.iter().map(|idx| *idx as u8).collect(),
            data: value.data.clone(),
        }
    }
}

impl From<&proto::MessageAddressTableLookup> for MessageAddressTableLookup {
    fn from(value: &proto::MessageAddressTableLookup) -> Self {
        MessageAddressTableLookup {
            account_key: Pubkey::new_from_array(value.account_key.clone().try_into().unwrap()),
            writable_indexes: value
                .writable_indexes
                .iter()
                .map(|idx| *idx as u8)
                .collect(),
            readonly_indexes: value
                .readonly_indexes
                .iter()
                .map(|idx| *idx as u8)
                .collect(),
        }
    }
}

/* Returns (txn_err, instr_err, custom_err, instr_err_idx) */
fn transaction_error_to_err_nums(transaction_error: &TransactionError) -> (u32, u32, u32, u32) {
    let (instr_err_no, custom_err_no, instr_err_idx) = match transaction_error.clone() {
        TransactionError::InstructionError(instr_err_idx, instruction_error) => {
            let instr_err_no = {
                let serialized = bincode::serialize(&instruction_error).unwrap_or(vec![0, 0, 0, 0]);
                u32::from_le_bytes(serialized[0..4].try_into().unwrap()).saturating_add(1)
            };
            let custom_err_no = match instruction_error {
                InstructionError::Custom(custom_err_no) => custom_err_no,
                _ => 0,
            };
            (instr_err_no, custom_err_no, instr_err_idx)
        }
        _ => (0, 0, 0),
    };
    let txn_err_no = {
        let serialized = bincode::serialize(&transaction_error).unwrap_or(vec![0, 0, 0, 0]);
        u32::from_le_bytes(serialized[0..4].try_into().unwrap()).saturating_add(1)
    };
    (
        txn_err_no,
        instr_err_no,
        custom_err_no,
        instr_err_idx.into(),
    )
}

// A tuple of a pubkey and an AccountSharedData represents a TransactionAccount.
impl From<KeyedAccountSharedData> for AcctState {
    fn from(value: KeyedAccountSharedData) -> AcctState {
        AcctState {
            address: value.0.to_bytes().to_vec(),
            lamports: value.1.lamports(),
            data: value.1.data().to_vec(),
            executable: value.1.executable(),
            owner: value.1.owner().to_bytes().to_vec(),
        }
    }
}

fn output_txn_result_from_result(
    value: LoadAndExecuteTransactionsOutput,
    sanitized_message: &SanitizedMessage,
) -> TxnResult {
    let execution_results = &value.processing_results[0];
    let (
        is_ok,
        sanitization_error,
        status,
        instruction_error,
        instruction_error_index,
        custom_error,
        executed_units,
        return_data,
        fee_details,
        loaded_accounts_data_size,
        modified_accounts,
        rollback_accounts,
    ) = match execution_results {
        Ok(txn) => {
            let (status, instr_err, custom_err, instr_err_idx) =
                match txn.status().as_ref().map_err(transaction_error_to_err_nums) {
                    Ok(_) => (0, 0, 0, 0),
                    Err((status, instr_err, custom_err, instr_err_idx)) => {
                        // Set custom err to 0 if the failing instruction is a precompile
                        let custom_err_ret = sanitized_message
                            .instructions()
                            .get(instr_err_idx as usize)
                            .and_then(|instr| {
                                sanitized_message
                                    .account_keys()
                                    .get(instr.program_id_index as usize)
                                    .map(|program_id| {
                                        if get_precompile(program_id, |_| true).is_some() {
                                            0
                                        } else {
                                            custom_err
                                        }
                                    })
                            })
                            .unwrap_or(custom_err);
                        (status, instr_err, custom_err_ret, instr_err_idx)
                    }
                };

            /* We want to collect modified accounts as well as any rollback accounts for failed transactions */
            let (modified_accounts, rollback_accounts) = match txn {
                ProcessedTransaction::Executed(executed_tx) => {
                    let loaded_transaction = &executed_tx.loaded_transaction;
                    let modified_accounts = loaded_transaction
                        .accounts
                        .clone()
                        .into_iter()
                        .enumerate()
                        .filter(|&(i, _)| sanitized_message.is_writable(i))
                        .map(|(_, account)| account)
                        .collect();

                    let rollback_accounts: Vec<KeyedAccountSharedData> =
                        if executed_tx.execution_details.status.is_err() {
                            loaded_transaction
                                .rollback_accounts
                                .iter()
                                .cloned()
                                .collect()
                        } else {
                            vec![]
                        };

                    (modified_accounts, rollback_accounts)
                }
                ProcessedTransaction::FeesOnly(tx) => {
                    let rollback_accounts = tx.rollback_accounts.iter().cloned().collect();
                    (vec![], rollback_accounts)
                }
            };
            let return_data = match txn {
                ProcessedTransaction::Executed(executed_tx) => executed_tx
                    .execution_details
                    .return_data
                    .as_ref()
                    .map(|info| info.clone().data)
                    .unwrap_or_default(),
                ProcessedTransaction::FeesOnly(_) => vec![],
            };
            (
                execution_results.was_processed_with_successful_result(),
                false,
                status,
                instr_err,
                instr_err_idx,
                custom_err,
                txn.executed_units(),
                return_data,
                Some(txn.fee_details()),
                txn.loaded_accounts_data_size(),
                modified_accounts,
                rollback_accounts,
            )
        }
        Err(transaction_error) => {
            let (status, instr_err, custom_err, instr_err_idx) =
                transaction_error_to_err_nums(transaction_error);
            (
                false,
                true,
                status,
                instr_err,
                instr_err_idx,
                custom_err,
                0,
                vec![],
                None,
                0,
                vec![],
                vec![],
            )
        }
    };

    TxnResult {
        executed: execution_results.was_processed(),
        sanitization_error,
        is_ok,
        status,
        instruction_error,
        instruction_error_index,
        custom_error,
        return_data,
        executed_units,
        fee_details: fee_details.map(|fees| proto::FeeDetails {
            transaction_fee: fees.transaction_fee(),
            prioritization_fee: fees.prioritization_fee(),
        }),
        loaded_accounts_data_size: loaded_accounts_data_size as u64,
        modified_accounts: modified_accounts
            .into_iter()
            .map(|account| account.into())
            .collect(),
        rollback_accounts: rollback_accounts
            .into_iter()
            .map(|account| account.into())
            .collect(),
    }
}

#[allow(deprecated)]
pub fn execute_transaction(context: &TxnContext) -> Option<TxnResult> {
    let txn_bank = context.bank.as_ref().unwrap();

    let accounts_to_store = context
        .account_shared_data
        .iter()
        .map(|account| {
            let pubkey = Pubkey::new_from_array(account.address.clone().try_into().unwrap());
            let account_data = AccountSharedData::from(account);
            (pubkey, account_data)
        })
        .collect::<Vec<_>>();

    /* Construct blockhash queue */
    let mut blockhash_queue = BlockhashQueue::default();
    txn_bank.blockhash_queue.iter().for_each(|element| {
        let blockhash_hash = Hash::new_from_array(element.blockhash.clone().try_into().unwrap());
        blockhash_queue.register_hash(&blockhash_hash, element.lamports_per_signature);
    });

    /* Construct fee rate governor. On snapshot boot the fee rate governor's
    lamports_per_signature is obtained from the manifest so we can
    just directly use that value here. */
    let input_fee_rate_governor = txn_bank.fee_rate_governor.as_ref().unwrap();
    let fee_rate_governor = FeeRateGovernor {
        lamports_per_signature: txn_bank.rbh_lamports_per_signature as u64,
        target_lamports_per_signature: input_fee_rate_governor.target_lamports_per_signature,
        target_signatures_per_slot: input_fee_rate_governor.target_signatures_per_slot,
        min_lamports_per_signature: input_fee_rate_governor.min_lamports_per_signature,
        max_lamports_per_signature: input_fee_rate_governor.max_lamports_per_signature,
        burn_percent: input_fee_rate_governor.burn_percent as u8,
    };

    /* Slot and parent slot */
    let clock: Clock = accounts_to_store
        .iter()
        .find(|(address, account)| address == &solana_sysvar::clock::id() && account.lamports() > 0)
        .and_then(|(_, account)| bincode::deserialize(account.data()).ok())
        .unwrap();
    let slot = clock.slot;
    let parent_slot = slot.saturating_sub(1);
    assert!(slot > 0);

    /* Total epoch stake */
    let total_epoch_stake = txn_bank.total_epoch_stake;

    /* Epoch schedule */
    let input_epoch_schedule = txn_bank.epoch_schedule.as_ref().unwrap();
    let epoch_schedule = EpochSchedule {
        slots_per_epoch: input_epoch_schedule.slots_per_epoch,
        leader_schedule_slot_offset: input_epoch_schedule.leader_schedule_slot_offset,
        warmup: input_epoch_schedule.warmup,
        first_normal_epoch: input_epoch_schedule.first_normal_epoch,
        first_normal_slot: input_epoch_schedule.first_normal_slot,
    };

    /* Rent */
    let input_rent = txn_bank.rent.as_ref().unwrap();
    let rent = Rent {
        lamports_per_byte_year: input_rent.lamports_per_byte_year,
        exemption_threshold: input_rent.exemption_threshold,
        burn_percent: input_rent.burn_percent as u8,
    };

    /* Feature set */
    let feature_set = FeatureSet::from(txn_bank.features.as_ref().unwrap());

    /* Epoch */
    let epoch = txn_bank.epoch;

    /* Set up accounts DB and populate account states from input */
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit_mb: IndexLimitMb::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = AccountsDbConfig {
        index,
        storage_access: StorageAccess::File,
        skip_initial_hash_calc: true,
        ..AccountsDbConfig::default()
    };
    let accounts_db = AccountsDb::new_with_config(
        vec!["/dev/shm/a".into()],
        accounts_db_config,
        None,
        Arc::new(AtomicBool::new(false)),
    );
    let accounts = Accounts::new(Arc::new(accounts_db));
    accounts.store_accounts_seq((parent_slot, &accounts_to_store[..]), None);
    accounts.accounts_db.add_root(parent_slot);

    /* Create the bank RC */
    let bank_rc = BankRc::new(accounts);

    /* Create a dummy versioned epoch stakes hashmap with a single entry at epoch + 1,
    and set the total epoch stake */
    let mut epoch_stakes: HashMap<Epoch, VersionedEpochStakes> = HashMap::new();
    for key in [epoch, epoch.saturating_add(1)] {
        let mut entry = VersionedEpochStakes::new(
            SerdeStakesToStakeFormat::Stake(Stakes::<Stake>::default()),
            key,
        );
        entry.set_total_stake(total_epoch_stake);
        epoch_stakes.insert(key, entry);
    }

    let bank_fields = BankFieldsToDeserialize {
        blockhash_queue,
        ancestors: AncestorsForSerialization::default(),
        hash: Hash::default(),        /* Unused */
        parent_hash: Hash::default(), /* Unused */
        parent_slot,
        hard_forks: HardForks::default(),        /* Unused */
        transaction_count: 0,                    /* Unused */
        hashes_per_tick: None,                   /* Unused */
        capitalization: 0,                       /* Unused */
        signature_count: 0,                      /* Unused */
        tick_height: 64u64.saturating_mul(slot), /* Unused */
        max_tick_height: 64u64.saturating_mul(slot.saturating_add(1)), /* Unused */
        ticks_per_slot: 64u64,                   /* Unused */
        ns_per_slot: 0,                          /* Unused */
        genesis_creation_time: 0,                /* Unused */
        slots_per_year: 0f64,                    /* Unused */
        slot,
        epoch,
        block_height: slot,              /* Unused */
        collector_id: Pubkey::default(), /* Unused */
        collector_fees: 0,               /* Unused */
        fee_rate_governor,
        rent_collector: RentCollector {
            epoch,
            epoch_schedule: epoch_schedule.clone(), /* Unused */
            slots_per_year: 0f64,                   /* Unused */
            rent,
        },
        epoch_schedule,
        inflation: Inflation::default(),         /* Unused */
        stakes: Stakes::<Delegation>::default(), /* Unused */
        versioned_epoch_stakes: epoch_stakes,    /* Unused */
        is_delta: false,                         /* Unused */
        accounts_data_len: 0,                    /* Unused */
        accounts_lt_hash: AccountsLtHash(LtHash::identity()), /* Unused */
        bank_hash_stats: BankHashStats::default(), /* Unused */
    };

    /* Finally create the bank and wrap in BankForks to set up the fork graph
    in the program cache (required by the transaction processor). */
    let bank = Bank::new_for_txn_fuzzing(bank_rc, bank_fields, feature_set);
    let bank_forks = BankForks::new_rw_arc(bank);
    let bank = bank_forks.read().unwrap().root_bank();

    /* Build the transaction from input */
    let message = build_versioned_message(context.tx.as_ref()?.message.as_ref()?);

    let mut signatures = context
        .tx
        .as_ref()?
        .signatures
        .iter()
        .map(|item| {
            Signature::from(<Vec<u8> as TryInto<[u8; 64]>>::try_into(item.clone()).unwrap())
        })
        .collect::<Vec<Signature>>();
    if signatures.is_empty() {
        // Default: valid txn with 1 empty signature (this keeps tests simpler)
        signatures.push(Signature::default());
    }

    let versioned_transaction = VersionedTransaction {
        message,
        signatures,
    };

    let runtime_transaction = match bank.verify_transaction(
        versioned_transaction,
        TransactionVerificationMode::HashAndVerifyPrecompiles,
    ) {
        Ok(v) => v,
        Err(e) => {
            let (status, instruction_error, _custom_error, instruction_error_index) =
                transaction_error_to_err_nums(&e);
            return Some(TxnResult {
                executed: false,
                sanitization_error: true,
                is_ok: false,
                status,
                instruction_error,
                instruction_error_index,
                custom_error: 0, // TODO: precompile error codes are not conformant, so we're ignoring custom error codes for now. This should be revisited in the future.
                return_data: vec![],
                executed_units: 0,
                fee_details: None,
                loaded_accounts_data_size: 0,
                modified_accounts: vec![],
                rollback_accounts: vec![],
            });
        }
    };

    // Agave v3.1 wraps txns in RuntimeTransaction, which is not clonable. We
    // need to wrap it in a Vec to satisfy the bank's prepare_sanitized_batch()
    let transactions = vec![runtime_transaction];
    let batch = bank.prepare_sanitized_batch(&transactions);

    let recording_config = ExecutionRecordingConfig {
        enable_cpi_recording: false,
        enable_log_recording: true,
        enable_return_data_recording: true,
        enable_transaction_balance_recording: false,
    };

    let mut timings = ExecuteTimings::default();

    let configs = TransactionProcessingConfig {
        account_overrides: None,
        check_program_modification_slot: false,
        log_messages_bytes_limit: None,
        limit_to_load_programs: true,
        recording_config,
    };

    let mut metrics = TransactionErrorMetrics::default();
    let result = bank.load_and_execute_transactions(
        &batch,
        MAX_PROCESSING_AGE,
        &mut timings,
        &mut metrics,
        configs,
    );

    // Agave v3.1 wraps txns in RuntimeTransaction, which is not clonable.
    // Therefore, we need to borrow the runtime_transaction from the Vec.
    let runtime_transaction_ref = &transactions[0];

    let account_keys = context
        .tx
        .as_ref()
        .and_then(|tx| tx.message.as_ref())
        .map(|message| message.account_keys.clone())
        .unwrap_or_default();

    let mut txn_result = output_txn_result_from_result(result, runtime_transaction_ref.message());

    // Only keep accounts that were passed in as account_keys or as ALUT accounts
    let mut loaded_account_keys = AHashSet::<Pubkey>::new();
    loaded_account_keys.extend(
        account_keys
            .iter()
            .map(|key| Pubkey::new_from_array(key.clone().try_into().ok().unwrap())),
    );
    match runtime_transaction_ref.message() {
        SanitizedMessage::Legacy(_) => {}
        SanitizedMessage::V0(message) => {
            loaded_account_keys.extend(message.loaded_addresses.writable.clone().iter());
            loaded_account_keys.extend(message.loaded_addresses.readonly.clone().iter());
        }
    }
    txn_result.modified_accounts.retain(|account| {
        loaded_account_keys.contains(&Pubkey::new_from_array(
            account.address.clone().try_into().unwrap(),
        ))
    });

    Some(txn_result)
}
