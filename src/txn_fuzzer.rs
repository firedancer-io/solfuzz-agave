use crate::proto::{self, ResultingState};
use crate::proto::{AcctState, TransactionMessage, TxnContext, TxnResult};
use prost::Message;
use solana_accounts_db::accounts_db::{AccountShrinkThreshold, AccountsDbConfig};
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_index::{
    AccountSecondaryIndexes, AccountsIndexConfig, IndexLimitMb,
};
use solana_program::hash::Hash;
use solana_program::instruction::CompiledInstruction;
use solana_program::message::v0::{LoadedAddresses, MessageAddressTableLookup};
use solana_program::message::{
    legacy, v0, AddressLoader, AddressLoaderError, MessageHeader, VersionedMessage,
};
use solana_program::pubkey::Pubkey;
use solana_runtime::bank::builtins::BUILTINS;
use solana_runtime::bank::{Bank, LoadAndExecuteTransactionsOutput};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::transaction_batch::TransactionBatch;
use solana_sdk::account::{AccountSharedData, ReadableAccount};
use solana_sdk::feature_set::FeatureSet;
use solana_sdk::genesis_config::GenesisConfig;
use solana_sdk::instruction::InstructionError;
use solana_sdk::rent::Rent;
use solana_sdk::signature::Signature;
use solana_sdk::sysvar;
use solana_sdk::transaction::{
    SanitizedTransaction, SanitizedVersionedTransaction, TransactionError, VersionedTransaction,
};
use solana_sdk::transaction_context::TransactionAccount;
use solana_svm::account_loader::LoadedTransaction;
use solana_svm::runtime_config::RuntimeConfig;
use solana_svm::transaction_error_metrics::TransactionErrorMetrics;
use solana_svm::transaction_processing_result::{
    ProcessedTransaction, TransactionProcessingResultExtensions,
};
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionProcessingConfig};
use solana_timings::ExecuteTimings;
use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::c_int;
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
    let txn_context = match TxnContext::decode(&in_slice[..in_sz as usize]) {
        Ok(context) => context,
        Err(_) => return 0, // Decode error
    };

    let txn_result = match execute_transaction(txn_context) {
        Some(value) => value,
        None => return 0, // Data format error
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
            num_required_signatures: value.num_required_signatures as u8,
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

impl From<&proto::LoadedAddresses> for LoadedAddresses {
    fn from(value: &proto::LoadedAddresses) -> Self {
        LoadedAddresses {
            writable: value
                .writable
                .iter()
                .map(|item| Pubkey::new_from_array(item.clone().try_into().unwrap()))
                .collect(),
            readonly: value
                .readonly
                .iter()
                .map(|item| Pubkey::new_from_array(item.clone().try_into().unwrap()))
                .collect(),
        }
    }
}

fn build_versioned_message(value: &TransactionMessage) -> Option<VersionedMessage> {
    let header = if let Some(value_header) = value.header {
        MessageHeader::from(&value_header)
    } else {
        // Default: valid txn header with 1 signature (this keeps tests simpler)
        MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        }
    };
    let account_keys = value
        .account_keys
        .iter()
        .map(|key| Pubkey::new_from_array(key.clone().try_into().unwrap()))
        .collect::<Vec<Pubkey>>();
    let recent_blockhash = if value.recent_blockhash.is_empty() {
        // Default: empty blockchash (this keeps tests simpler)
        Hash::new_from_array([0u8; 32])
    } else {
        Hash::new(&value.recent_blockhash)
    };
    let instructions = value
        .instructions
        .iter()
        .map(CompiledInstruction::from)
        .collect::<Vec<CompiledInstruction>>();

    if value.is_legacy {
        let message = legacy::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        };
        Some(VersionedMessage::Legacy(message))
    } else {
        let address_table_lookups = value
            .address_table_lookups
            .iter()
            .map(MessageAddressTableLookup::from)
            .collect::<Vec<MessageAddressTableLookup>>();

        let message = v0::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups,
        };

        Some(VersionedMessage::V0(message))
    }
}

#[derive(Clone)]
struct MockAddressLoader {
    loaded_addresses: LoadedAddresses,
}

impl AddressLoader for MockAddressLoader {
    fn load_addresses(
        mut self,
        _lookups: &[MessageAddressTableLookup],
    ) -> Result<LoadedAddresses, AddressLoaderError> {
        Ok(std::mem::take(&mut self.loaded_addresses))
    }
}

impl From<TransactionAccount> for proto::AcctState {
    fn from(value: TransactionAccount) -> AcctState {
        AcctState {
            address: value.0.to_bytes().to_vec(),
            lamports: value.1.lamports(),
            data: value.1.data().to_vec(),
            executable: value.1.executable(),
            rent_epoch: value.1.rent_epoch(),
            owner: value.1.owner().to_bytes().to_vec(),
            seed_addr: None,
        }
    }
}

impl From<LoadedTransaction> for proto::ResultingState {
    fn from(value: LoadedTransaction) -> proto::ResultingState {
        let rent_debits = value
            .rent_debits
            .into_unordered_rewards_iter()
            .map(|(key, value)| proto::RentDebits {
                pubkey: key.to_bytes().to_vec(),
                rent_collected: value.lamports,
            })
            .collect::<Vec<proto::RentDebits>>();

        let mut acct_states: Vec<AcctState> = Vec::with_capacity(value.accounts.len());

        for item in value.accounts {
            acct_states.push(item.into());
        }

        proto::ResultingState {
            acct_states,
            rent_debits,
            transaction_rent: value.rent,
        }
    }
}

impl From<LoadAndExecuteTransactionsOutput> for TxnResult {
    fn from(value: LoadAndExecuteTransactionsOutput) -> TxnResult {
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
            rent,
            resulting_state,
        ) = match execution_results {
            Ok(txn) => {
                let is_ok = match txn {
                    ProcessedTransaction::Executed(executed_tx) => {
                        executed_tx.execution_details.status.is_ok()
                    }
                    ProcessedTransaction::FeesOnly(_) => false,
                };
                let transaction_error = txn.status();
                let (instr_err_idx, instruction_error) = match transaction_error.as_ref() {
                    Err(TransactionError::InstructionError(instr_err_idx, instr_err)) => {
                        (*instr_err_idx, Some(instr_err.clone()))
                    }
                    _ => (0, None),
                };
                let custom_error = match instruction_error {
                    Some(InstructionError::Custom(custom_error)) => custom_error,
                    _ => 0,
                };

                let status = match transaction_error {
                    Ok(_) => 0,
                    Err(transaction_error) => {
                        let serialized =
                            bincode::serialize(&transaction_error).unwrap_or(vec![0, 0, 0, 0]);
                        u32::from_le_bytes(serialized[0..4].try_into().unwrap()) + 1
                    }
                };
                let instr_err_no = match instruction_error {
                    Some(instruction_error) => {
                        let serialized =
                            bincode::serialize(&instruction_error).unwrap_or(vec![0, 0, 0, 0]);
                        u32::from_le_bytes(serialized[0..4].try_into().unwrap()) + 1
                    }
                    None => 0,
                };
                let rent = match txn {
                    ProcessedTransaction::Executed(executed_tx) => {
                        executed_tx.loaded_transaction.rent
                    }
                    ProcessedTransaction::FeesOnly(_) => 0,
                };
                let resulting_state: Option<ResultingState> = match txn {
                    ProcessedTransaction::Executed(executed_tx) => {
                        Some(executed_tx.loaded_transaction.clone().into())
                    }
                    ProcessedTransaction::FeesOnly(_) => None,
                };
                let executed_units = match txn {
                    ProcessedTransaction::Executed(executed_tx) => {
                        executed_tx.execution_details.executed_units
                    }
                    ProcessedTransaction::FeesOnly(_) => 0,
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
                    is_ok,
                    false,
                    status,
                    instr_err_no,
                    instr_err_idx,
                    custom_error,
                    executed_units,
                    return_data,
                    Some(txn.fee_details()),
                    rent,
                    resulting_state,
                )
            }
            Err(error) => {
                let serialized = bincode::serialize(error).unwrap_or(vec![0, 0, 0, 0]);
                let error_no = u32::from_le_bytes(serialized[0..4].try_into().unwrap()) + 1;
                (false, true, error_no, 0, 0, 0, 0, vec![], None, 0, None)
            }
        };

        TxnResult {
            executed: execution_results.was_processed(),
            sanitization_error,
            resulting_state,
            rent,
            is_ok,
            status,
            instruction_error,
            instruction_error_index: instruction_error_index.into(),
            custom_error,
            return_data,
            executed_units,
            fee_details: fee_details.map(|fees| proto::FeeDetails {
                transaction_fee: fees.transaction_fee(),
                prioritization_fee: fees.prioritization_fee(),
            }),
        }
    }
}

#[allow(deprecated)]
fn execute_transaction(context: TxnContext) -> Option<TxnResult> {
    let fd_features = context
        .epoch_ctx
        .as_ref()
        .map(|ctx| ctx.features.clone().unwrap_or_default())
        .unwrap_or_default();

    let feature_set = FeatureSet::from(&fd_features);
    let fee_collector = Pubkey::new_unique();
    let slot = context.slot_ctx.as_ref().map(|ctx| ctx.slot).unwrap_or(10); // Arbitrary default > 0

    /* HACK: Set the genesis config rent from the "to-be" sysvar rent, if present */
    let rent: Rent = context
        .tx
        .as_ref()?
        .message
        .as_ref()?
        .account_shared_data
        .iter()
        .find(|item| item.address.as_slice() == sysvar::rent::id().as_ref())
        .map(|account| bincode::deserialize(&account.data).ok())
        .unwrap_or_default()
        .unwrap_or_default();

    let genesis_config = GenesisConfig {
        creation_time: 0,
        rent,
        ..GenesisConfig::default()
    };

    let mut blockhash_queue = context.blockhash_queue;
    let genesis_hash = if blockhash_queue.is_empty() {
        None
    } else {
        Some(Hash::new(blockhash_queue[0].as_slice()))
    };

    // Bank on slot 0
    let index = Some(AccountsIndexConfig {
        bins: Some(4),
        flush_threads: Some(1),
        index_limit_mb: IndexLimitMb::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = Some(AccountsDbConfig {
        index,
        storage_access: StorageAccess::File,
        skip_initial_hash_calc: true,
        ..AccountsDbConfig::default()
    });
    let mut bank = Bank::new_with_paths(
        &genesis_config,
        Arc::new(RuntimeConfig::default()),
        vec![],
        None,
        None,
        AccountSecondaryIndexes::default(),
        AccountShrinkThreshold::default(),
        false,
        accounts_db_config,
        None,
        Some(fee_collector),
        Arc::new(AtomicBool::new(false)),
        genesis_hash,
        Some(feature_set.clone()),
    );
    let bank_forks = BankForks::new_rw_arc(bank);
    let mut bank = bank_forks.read().unwrap().root_bank();
    bank.rehash();

    if slot > 0 {
        let new_bank = Bank::new_from_parent(bank.clone(), &fee_collector, slot);
        bank = bank_forks
            .write()
            .unwrap()
            .insert(new_bank)
            .clone_without_scheduler();
        bank.get_transaction_processor()
            .program_cache
            .write()
            .unwrap()
            .prune(slot, bank.epoch());
    }

    let account_keys = context
        .tx
        .as_ref()
        .and_then(|tx| tx.message.as_ref())
        .map(|message| message.account_keys.clone())
        .unwrap_or_default();
    let loaded_account_keys_writable = context
        .tx
        .as_ref()
        .and_then(|tx| tx.message.as_ref())
        .and_then(|message| message.loaded_addresses.as_ref())
        .map(|addresses| addresses.writable.clone())
        .unwrap_or_default();
    let loaded_account_keys_readonly = context
        .tx
        .as_ref()
        .and_then(|tx| tx.message.as_ref())
        .and_then(|message| message.loaded_addresses.as_ref())
        .map(|addresses| addresses.readonly.clone())
        .unwrap_or_default();

    /* Save loaded builtins so we don't load them twice */
    let mut stored_accounts = HashSet::<Pubkey>::default();
    for builtin in BUILTINS.iter() {
        if let Some(enable_feature_id) = builtin.enable_feature_id {
            if !bank.feature_set.is_active(&enable_feature_id) {
                continue;
            }
        }
        let pubkey = builtin.program_id;
        stored_accounts.insert(pubkey);
    }

    /* Load accounts + sysvars
    NOTE: Like in FD, we store the first instance of an account's state for a given pubkey. Account states of already-seen
    pubkeys are ignored. */
    bank.get_transaction_processor().reset_sysvar_cache();
    for account in &context.tx.as_ref()?.message.as_ref()?.account_shared_data {
        let pubkey = Pubkey::new_from_array(account.address.clone().try_into().ok()?);
        if !stored_accounts.insert(pubkey) {
            continue;
        }
        let account_data = AccountSharedData::from(account);
        bank.store_account(&pubkey, &account_data);
    }
    bank.get_transaction_processor()
        .fill_missing_sysvar_cache_entries(bank.as_ref());

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
    for blockhash in blockhash_queue.iter_mut() {
        let blockhash_hash = Hash::new_from_array(std::mem::take(blockhash).try_into().unwrap());
        bank.register_recent_blockhash_for_test(&blockhash_hash, lamports_per_signature);
    }
    bank.update_recent_blockhashes();

    let message = build_versioned_message(context.tx.as_ref()?.message.as_ref()?)?;

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

    let sanitized_versioned_transaction =
        match SanitizedVersionedTransaction::try_new(versioned_transaction) {
            Ok(v) => v,
            Err(_err) => {
                return Some(TxnResult {
                    executed: false,
                    sanitization_error: true,
                    resulting_state: None,
                    rent: 0,
                    is_ok: false,
                    status: 0,
                    instruction_error: 0,
                    instruction_error_index: 0,
                    custom_error: 0,
                    return_data: vec![],
                    executed_units: 0,
                    fee_details: None,
                })
            }
        };

    let mock_loader = MockAddressLoader {
        loaded_addresses: context
            .tx
            .as_ref()?
            .message
            .as_ref()?
            .loaded_addresses
            .as_ref()
            .map(LoadedAddresses::from)
            .unwrap_or_default(),
    };

    let message_hash = &context.tx.as_ref()?.message_hash;
    let message_hash = if message_hash.is_empty() {
        // Default: empty message hash (this keeps tests simpler)
        // Note: firedancer doesn't use message hash
        Hash::new_from_array([0u8; 32])
    } else {
        Hash::new(message_hash)
    };
    let sanitized_transaction = match SanitizedTransaction::try_new(
        sanitized_versioned_transaction,
        message_hash,
        context.tx?.is_simple_vote_tx,
        mock_loader,
        bank.get_reserved_account_keys(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let err = bincode::serialize(&e).unwrap_or(vec![0, 0, 0, 0]);
            let status = u32::from_le_bytes(err.try_into().unwrap()) + 1;
            return Some(TxnResult {
                executed: false,
                sanitization_error: false,
                resulting_state: None,
                rent: 0,
                is_ok: false,
                status,
                instruction_error: 0,
                instruction_error_index: 0,
                custom_error: 0,
                return_data: vec![],
                executed_units: 0,
                fee_details: None,
            });
        }
    };

    // Verify precompiles
    let pre_result = sanitized_transaction.verify_precompiles(&feature_set);
    if let Err(pre_error) = pre_result {
        let serialized = bincode::serialize(&pre_error).unwrap_or(vec![0, 0, 0, 0]);
        let status = u32::from_le_bytes(serialized[0..4].try_into().unwrap()) + 1;
        // Some of the values are sort of arbitrary, they're set to match Firedancer behavior
        // For example, sanitization_error: true.
        return Some(TxnResult {
            executed: false,
            sanitization_error: true,
            resulting_state: None,
            rent: 0,
            is_ok: false,
            status,
            instruction_error: 0,
            instruction_error_index: 0,
            custom_error: 0,
            return_data: vec![],
            executed_units: 0,
            fee_details: None,
        });
    }

    let transactions = [sanitized_transaction];

    let lock_results = bank.rc.accounts.lock_accounts(transactions.iter(), 64);

    let batch = TransactionBatch::new(lock_results, &bank, Cow::Borrowed(&transactions));

    let recording_config = ExecutionRecordingConfig {
        enable_cpi_recording: false,
        enable_log_recording: true,
        enable_return_data_recording: true,
    };

    let mut timings = ExecuteTimings::default();

    let configs = TransactionProcessingConfig {
        account_overrides: None,
        compute_budget: bank.compute_budget(),
        log_messages_bytes_limit: None,
        limit_to_load_programs: true,
        recording_config,
        transaction_account_lock_limit: None,
        check_program_modification_slot: false,
    };

    let mut metrics = TransactionErrorMetrics::default();
    let result = bank.load_and_execute_transactions(
        &batch,
        context.max_age as usize,
        &mut timings,
        &mut metrics,
        configs,
    );

    // Only keep accounts that were passed in as account_keys
    let mut txn_result: TxnResult = result.into();
    if let Some(relevant_accounts) = &mut txn_result.resulting_state {
        relevant_accounts.acct_states.retain(|account| {
            let pubkey = Pubkey::new_from_array(account.address.clone().try_into().ok().unwrap());
            (account_keys.contains(&account.address)
                || loaded_account_keys_writable.contains(&account.address)
                || loaded_account_keys_readonly.contains(&account.address))
                && pubkey != sysvar::instructions::id()
        });

        // Fill values for executable accounts with no lamports reported in output (this metadata was omitted by Agave for performance reasons)
        for account in relevant_accounts.acct_states.iter_mut() {
            if account.lamports == 0 && account.executable {
                let account_data = bank.get_account(&Pubkey::new_from_array(
                    account.address.clone().try_into().unwrap(),
                ));
                if let Some(account_data) = account_data {
                    account.lamports = account_data.lamports();
                    account.data = account_data.data().to_vec();
                    account.rent_epoch = account_data.rent_epoch();
                }
            }
        }
        txn_result.resulting_state = Some(relevant_accounts.clone());
    }

    Some(txn_result)
}
