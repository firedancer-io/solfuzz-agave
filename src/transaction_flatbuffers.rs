use crate::context_generated;
use crate::txn_generated;
use crate::utils::err_map_flatbuffers::{instr_err_to_num, txn_err_to_num};
use crate::utils::program::common_flatbuffers::build_output_account;
use crate::utils::program::common_flatbuffers::{
    build_versioned_transaction, get_dummy_bpf_native_programs, get_sysvar,
};
use agave_feature_set::*;
use agave_precompiles::get_precompile;
use ahash::AHashSet;
use solana_account::AccountSharedData;
use solana_accounts_db::accounts_db::AccountsDbConfig;
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimitMb};
use solana_clock::{Clock, MAX_PROCESSING_AGE};
use solana_epoch_schedule::EpochSchedule;
use solana_genesis_config::GenesisConfig;
use solana_hash::Hash;
use solana_instruction::error::InstructionError;
use solana_message::SanitizedMessage;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_runtime::account_saver::collect_accounts_for_failed_tx;
use solana_runtime::bank::{Bank, LoadAndExecuteTransactionsOutput};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::runtime_config::RuntimeConfig;
use solana_sdk_ids::{address_lookup_table, config, stake};
use solana_svm::transaction_error_metrics::TransactionErrorMetrics;
use solana_svm::transaction_processing_result::ProcessedTransaction;
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionProcessingConfig};
use solana_svm_timings::ExecuteTimings;
use solana_sysvar;
use solana_transaction::TransactionVerificationMode;
use solana_transaction_error::TransactionError;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/* Returns (txn_err, instr_err, custom_err, instr_err_idx) */
fn transaction_error_to_err_nums(transaction_error: &TransactionError) -> (u8, u8, u32, u8) {
    let (instr_err_no, custom_err_no, instr_err_idx) = match transaction_error.clone() {
        TransactionError::InstructionError(instr_err_idx, instruction_error) => {
            let instr_err_no = instr_err_to_num(&instruction_error);
            let custom_err_no = if let InstructionError::Custom(custom_err) = instruction_error {
                custom_err
            } else {
                0
            };
            (instr_err_no, custom_err_no, instr_err_idx)
        }
        _ => (0, 0, 0),
    };
    let txn_err_no = txn_err_to_num(transaction_error);
    (txn_err_no, instr_err_no, custom_err_no, instr_err_idx)
}

fn build_transaction_effects<'a>(
    txn_output: &LoadAndExecuteTransactionsOutput,
    sanitized_message: &SanitizedMessage,
    accounts_to_capture: &AHashSet<Pubkey>,
    builder: &mut flatbuffers::FlatBufferBuilder<'a>,
) -> flatbuffers::WIPOffset<txn_generated::TxnEffects<'a>> {
    /* Build scalar fields */
    let execution_results = &txn_output.processing_results[0];
    let (
        txn_err_code,
        instr_err_code,
        instr_err_idx,
        custom_err_code,
        executed_units,
        loaded_accounts_data_size,
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
            (
                status,
                instr_err,
                instr_err_idx,
                custom_err,
                txn.executed_units(),
                txn.loaded_accounts_data_size(),
            )
        }
        Err(transaction_error) => {
            let (status, instr_err, custom_err, instr_err_idx) =
                transaction_error_to_err_nums(transaction_error);
            (status, instr_err, instr_err_idx, custom_err, 0, 0)
        }
    };

    /* Build modified accounts */
    let modified_accounts = match execution_results {
        Ok(txn) => {
            let accounts_to_save = match txn {
                ProcessedTransaction::Executed(executed_tx) => executed_tx
                    .loaded_transaction
                    .accounts
                    .iter()
                    .enumerate()
                    .filter_map(|(i, (address, account))| {
                        (accounts_to_capture.contains(address) && sanitized_message.is_writable(i))
                            .then_some((address, account))
                    })
                    .map(|(address, account)| build_output_account(address, account, builder))
                    .collect::<Vec<_>>(),
                ProcessedTransaction::FeesOnly(tx) => {
                    let mut rollback_accounts = Vec::with_capacity(tx.rollback_accounts.count());
                    collect_accounts_for_failed_tx(
                        &mut rollback_accounts,
                        &mut None,
                        None,
                        &tx.rollback_accounts,
                    );
                    rollback_accounts
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &(address, account))| {
                            (accounts_to_capture.contains(address)
                                && sanitized_message.is_writable(i))
                            .then_some((address, account))
                        })
                        .map(|(address, account)| build_output_account(address, account, builder))
                        .collect::<Vec<_>>()
                }
            };
            Some(builder.create_vector_from_iter(accounts_to_save.iter()))
        }
        _ => None,
    };

    /* Build return data and fee details */
    let (return_data, fee_details) = match execution_results {
        Ok(txn) => {
            let return_data = match txn {
                ProcessedTransaction::Executed(executed_tx) => Some(
                    builder.create_vector(
                        executed_tx
                            .execution_details
                            .return_data
                            .as_ref()
                            .map(|info| info.clone().data)
                            .unwrap_or_default()
                            .as_ref(),
                    ),
                ),
                ProcessedTransaction::FeesOnly(_) => Some(builder.create_vector::<u8>(&[])),
            };
            let fee_details = Some(txn_generated::FeeDetails::create(
                builder,
                &txn_generated::FeeDetailsArgs {
                    transaction_fee: txn.fee_details().transaction_fee(),
                    prioritization_fee: txn.fee_details().prioritization_fee(),
                },
            ));
            (return_data, fee_details)
        }
        _ => (None, None),
    };

    /* Build the final transaction effects */
    txn_generated::TxnEffects::create(
        builder,
        &txn_generated::TxnEffectsArgs {
            txn_err_code,
            instr_err_code,
            instr_err_idx,
            custom_err_code,
            executed_units,
            loaded_accounts_data_size,
            modified_accounts,
            return_data,
            fee_details,
        },
    )
}

#[allow(deprecated)]
pub fn execute_transaction(
    context: &txn_generated::TxnContext<'_>,
    builder: &mut flatbuffers::FlatBufferBuilder<'_>,
) {
    let feature_set = if let Some(features) = context.features() {
        FeatureSet::from(&features)
    } else {
        FeatureSet::default()
    };

    const FEE_COLLECTOR: Pubkey = Pubkey::from_str_const("1111111111111111111111111111111111");

    /* Read sysvars from the input account states */
    let sysvar_accounts: HashMap<Pubkey, context_generated::Account> = context
        .account_states()
        .iter()
        .filter(|item| item.lamports() > 0)
        .map(|item| (item.address().into(), item))
        .collect();

    let rent: Rent = get_sysvar(&sysvar_accounts, &solana_sysvar::rent::id());
    let epoch_schedule: EpochSchedule =
        get_sysvar(&sysvar_accounts, &solana_sysvar::epoch_schedule::id());
    let clock: Clock = get_sysvar(&sysvar_accounts, &solana_sysvar::clock::id());

    let slot = clock.slot;

    /* HACK: Add dummy ALUT and config program accounts to genesis config so that their builtin versions don't get added to the program cache */
    let mut genesis_config = GenesisConfig {
        creation_time: 0,
        rent,
        epoch_schedule,
        ..GenesisConfig::default()
    };

    let bpf_native_program_accounts = get_dummy_bpf_native_programs();
    bpf_native_program_accounts
        .iter()
        .for_each(|(key, account)| {
            genesis_config.add_account(*key, account.clone());
        });

    let blockhash_queue = if context.blockhash_queue().is_empty() {
        vec![Hash::default()]
    } else {
        context
            .blockhash_queue()
            .iter()
            .map(|item| item.into())
            .collect()
    };
    let genesis_hash = Some(blockhash_queue[0]);

    // Bank on slot 0
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit_mb: IndexLimitMb::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    // create shm path for accountsdb to never touch disk
    #[allow(unused)]
    let shm_path = std::path::PathBuf::from("/dev/shm");

    let accounts_db_config = Some(AccountsDbConfig {
        index,
        storage_access: StorageAccess::Mmap,
        skip_initial_hash_calc: true,
        num_hash_threads: Some(NonZeroUsize::new(1).unwrap()),
        base_working_path: Some(shm_path),
        ..AccountsDbConfig::default()
    });
    let bank = Bank::new_with_paths(
        &genesis_config,
        Arc::new(RuntimeConfig::default()),
        vec!["/dev/shm/a".into()],
        None,
        None,
        false,
        accounts_db_config,
        None,
        Some(FEE_COLLECTOR),
        Arc::new(AtomicBool::new(false)),
        genesis_hash,
        Some(feature_set.clone()),
    );
    let bank_forks = BankForks::new_rw_arc(bank);
    let mut bank = bank_forks.read().unwrap().root_bank();
    bank.rehash();

    if slot > 0 {
        let new_bank = Bank::new_from_parent(bank.clone(), &FEE_COLLECTOR, slot);
        bank = bank_forks
            .write()
            .unwrap()
            .insert(new_bank)
            .clone_without_scheduler();
        bank.prune_program_cache(slot, bank.epoch());
    }

    /* Now remove the config and ALUT programs from the bank so they can be reloaded in properly */
    bank.store_account(&address_lookup_table::id(), &AccountSharedData::default());
    bank.store_account(&config::id(), &AccountSharedData::default());
    bank.store_account(&stake::id(), &AccountSharedData::default());

    /* Load accounts + sysvars
    NOTE: Like in FD, we store the first instance of an account's state for a given pubkey. Account states of already-seen
    pubkeys are ignored. */
    bank.get_transaction_processor().reset_sysvar_cache();
    context.account_states().iter().for_each(|account| {
        let pubkey = &account.address().into();
        let account_data = AccountSharedData::from(&account);
        bank.store_account(pubkey, &account_data);
    });
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(bank.as_ref());

    /* Update rent and epoch schedule sysvar accounts to the minimum rent exempt balance */
    bank.update_epoch_schedule();
    bank.update_rent();

    let sysvar_recent_blockhashes = bank.get_sysvar_cache_for_tests().get_recent_blockhashes();
    let mut lamports_per_signature: Option<u64> = None;
    if let Ok(recent_blockhashes) = &sysvar_recent_blockhashes {
        if let Some(hash) = recent_blockhashes.first() {
            if hash.fee_calculator.lamports_per_signature != 0 {
                lamports_per_signature = Some(hash.fee_calculator.lamports_per_signature);
            }
        }
    }

    // Register blockhashes in bank
    blockhash_queue.iter().for_each(|blockhash| {
        bank.register_recent_blockhash_for_test(&blockhash, lamports_per_signature);
    });
    bank.update_recent_blockhashes();
    bank.get_transaction_processor().reset_sysvar_cache();
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(bank.as_ref());

    let versioned_transaction = build_versioned_transaction(&context.txn_message());
    let sanitized_transaction = match bank.verify_transaction(
        versioned_transaction,
        TransactionVerificationMode::HashAndVerifyPrecompiles,
    ) {
        Ok(v) => v,
        Err(e) => {
            let (txn_err_code, instr_err_code, custom_err_code, instr_err_idx) =
                transaction_error_to_err_nums(&e);
            let txn_effects = txn_generated::TxnEffects::create(
                builder,
                &txn_generated::TxnEffectsArgs {
                    txn_err_code,
                    instr_err_code,
                    instr_err_idx,
                    custom_err_code,
                    ..txn_generated::TxnEffectsArgs::default()
                },
            );
            builder.finish_minimal(txn_effects);
            return;
        }
    };

    let transactions = [sanitized_transaction.clone()];

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

    /* Build a set of account keys to capture */
    let loaded_addresses = sanitized_transaction.get_loaded_addresses();
    let accounts_to_capture: AHashSet<Pubkey> = context
        .txn_message()
        .account_keys()
        .iter()
        .map(|key| key.into())
        .chain(loaded_addresses.writable.into_iter())
        .chain(loaded_addresses.readonly.into_iter())
        .collect();

    /* Build transaction effects */
    let txn_effects = build_transaction_effects(
        &result,
        sanitized_transaction.message(),
        &accounts_to_capture,
        builder,
    );

    builder.finish_minimal(txn_effects);
}
