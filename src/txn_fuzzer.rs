use crate::proto;
use crate::proto::{AcctState, TransactionMessage, TxnContext, TxnResult};
use prost::Message;
use solana_accounts_db::accounts_db::AccountShrinkThreshold;
use solana_accounts_db::accounts_index::AccountSecondaryIndexes;
use solana_program::hash::Hash;
use solana_program::instruction::CompiledInstruction;
use solana_program::message::v0::{LoadedAddresses, MessageAddressTableLookup};
use solana_program::message::{
    legacy, v0, AddressLoader, AddressLoaderError, MessageHeader, VersionedMessage,
};
use solana_program::pubkey::Pubkey;
use solana_program_runtime::timings::ExecuteTimings;
use solana_runtime::bank::{Bank, LoadAndExecuteTransactionsOutput};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::transaction_batch::TransactionBatch;
use solana_sdk::account::{AccountSharedData, ReadableAccount};
use solana_sdk::feature_set::FeatureSet;
use solana_sdk::genesis_config::GenesisConfig;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::{
    SanitizedTransaction, SanitizedVersionedTransaction, TransactionError, VersionedTransaction,
};
use solana_sdk::transaction_context::TransactionAccount;
use solana_svm::account_loader::LoadedTransaction;
use solana_svm::runtime_config::RuntimeConfig;
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionProcessingConfig};
use std::borrow::Cow;
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
    let header = MessageHeader::from(value.header.as_ref()?);
    let account_keys = value
        .account_keys
        .iter()
        .map(|key| Pubkey::new_from_array(key.clone().try_into().unwrap()))
        .collect::<Vec<Pubkey>>();
    let recent_blockhash = Hash::new_from_array(value.recent_blockhash.clone().try_into().unwrap());
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
    fn from(mut value: LoadAndExecuteTransactionsOutput) -> TxnResult {
        let mut loaded_transaction = Err(TransactionError::AccountInUse);
        std::mem::swap(&mut value.loaded_transactions[0], &mut loaded_transaction);
        let execution_results = &value.execution_results[0];

        let (is_ok, status, executed_units, accounts_data_len_delta, return_data, fee_details) =
            if execution_results.was_executed() {
                let details = execution_results.details().unwrap();
                let is_ok = details.status.is_ok();
                let error = details
                    .status
                    .as_ref()
                    .err()
                    .unwrap_or(&TransactionError::AccountInUse);
                let serialized = bincode::serialize(error).unwrap_or(vec![0, 0, 0, 0]);
                let error_no = u32::from_le_bytes(serialized[0..4].try_into().unwrap());

                (
                    is_ok,
                    error_no,
                    details.executed_units,
                    details.accounts_data_len_delta,
                    details
                        .return_data
                        .as_ref()
                        .map(|info| info.data.clone())
                        .unwrap_or_default(),
                    Some(details.fee_details),
                )
            } else {
                (false, 0, 0, 0, vec![], None)
            };

        let rent = loaded_transaction
            .as_ref()
            .map(|txn| txn.rent)
            .unwrap_or_default();
        let resulting_state = if let Ok(txn) = loaded_transaction {
            Some(txn.into())
        } else {
            None
        };
        TxnResult {
            executed: execution_results.was_executed(),
            sanitization_error: false,
            resulting_state,
            rent,
            is_ok,
            status,
            return_data,
            executed_units,
            accounts_data_len_delta,
            fee_details: fee_details.map(|fees| proto::FeeDetails {
                transaction_fee: fees.transaction_fee(),
                prioritization_fee: fees.prioritization_fee(),
            }),
        }
    }
}

fn execute_transaction(context: TxnContext) -> Option<TxnResult> {
    let fd_features = context
        .epoch_ctx
        .as_ref()
        .map(|ctx| ctx.features.clone().unwrap_or_default())
        .unwrap_or_default();

    let feature_set = Arc::new(FeatureSet::from(&fd_features));
    let fee_collector = Pubkey::new_unique();
    let slot = context
        .slot_ctx
        .as_ref()
        .map(|ctx| ctx.slot)
        .unwrap_or_default();

    let genesis_config = GenesisConfig::default();

    let blockhash_queue = context.blockhash_queue;
    let genesis_hash = Hash::new(blockhash_queue[0].as_slice());

    // Bank on slot 0
    let mut bank = Bank::new_with_paths(
        &genesis_config,
        Arc::new(RuntimeConfig::default()),
        vec![],
        None,
        None,
        AccountSecondaryIndexes::default(),
        AccountShrinkThreshold::default(),
        false,
        None,
        None,
        Some(fee_collector),
        Arc::new(AtomicBool::new(false)),
        Some(genesis_hash),
    );
    bank.feature_set = feature_set.clone();
    let bank_forks = BankForks::new_rw_arc(bank);
    let mut bank = bank_forks.read().unwrap().root_bank();

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

    for account in &context.tx.as_ref()?.message.as_ref()?.account_shared_data {
        let pubkey = Pubkey::new_from_array(account.address.clone().try_into().ok()?);
        let account_data = AccountSharedData::from(account);

        bank.store_account(&pubkey, &account_data);
    }

    // Register blockhashes in bank
    for blockhash in blockhash_queue.iter() {
        let blockhash_hash = Hash::new_from_array(blockhash.clone().try_into().unwrap());
        bank.register_recent_blockhash_for_test(&blockhash_hash);
    }

    let message = build_versioned_message(context.tx.as_ref()?.message.as_ref()?)?;

    let signatures = context
        .tx
        .as_ref()?
        .signatures
        .iter()
        .map(|item| {
            Signature::from(<Vec<u8> as TryInto<[u8; 64]>>::try_into(item.clone()).unwrap())
        })
        .collect::<Vec<Signature>>();

    let versioned_transaction = VersionedTransaction {
        message,
        signatures,
    };

    let sanitized_versioned_transaction =
        match SanitizedVersionedTransaction::try_new(versioned_transaction) {
            Ok(v) => v,
            Err(_) => {
                return Some(TxnResult {
                    executed: false,
                    sanitization_error: true,
                    resulting_state: None,
                    rent: 0,
                    is_ok: false,
                    status: 0,
                    return_data: vec![],
                    executed_units: 0,
                    accounts_data_len_delta: 0,
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

    let sanitized_transaction = match SanitizedTransaction::try_new(
        sanitized_versioned_transaction,
        Hash::new_from_array(
            context
                .tx
                .as_ref()?
                .message_hash
                .clone()
                .try_into()
                .unwrap(),
        ),
        context.tx?.is_simple_vote_tx,
        mock_loader,
        bank.get_reserved_account_keys(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let err = bincode::serialize(&e).unwrap_or(vec![0, 0, 0, 0]);
            let status = u32::from_le_bytes(err.try_into().unwrap());
            return Some(TxnResult {
                executed: false,
                sanitization_error: false,
                resulting_state: None,
                rent: 0,
                is_ok: false,
                status,
                return_data: vec![],
                executed_units: 0,
                accounts_data_len_delta: 0,
                fee_details: None,
            });
        }
    };

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

    let result =
        bank.load_and_execute_transactions(&batch, context.max_age as usize, &mut timings, configs);

    // Only keep accounts that were passed in as account_keys
    let mut txn_result: TxnResult = result.into();
    if let Some(relevant_accounts) = &mut txn_result.resulting_state {
        relevant_accounts.acct_states.retain(|account| {
            account_keys.contains(&account.address)
                || loaded_account_keys_writable.contains(&account.address)
                || loaded_account_keys_readonly.contains(&account.address)
        });
    }

    Some(txn_result)
}
