use crate::proto::{self, ResultingState};
use crate::proto::{AcctState, TransactionMessage, TxnContext, TxnResult};
use prost::Message;
use solana_accounts_db::accounts_db::AccountShrinkThreshold;
use solana_accounts_db::accounts_index::{AccountSecondaryIndexes, ZeroLamport};
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_program::hash::Hash;
use solana_program::instruction::CompiledInstruction;
use solana_program::message::v0::{LoadedAddresses, MessageAddressTableLookup};
use solana_program::message::{
    legacy, v0, AddressLoader, AddressLoaderError, MessageHeader, VersionedMessage,
};
use solana_program::pubkey::Pubkey;
use solana_program_runtime::loaded_programs::{BlockRelation, ForkGraph, ProgramCacheEntry};
use solana_program_runtime::sysvar_cache;
use solana_runtime::bank::builtins::BUILTINS;
use solana_runtime::bank::{Bank, LoadAndExecuteTransactionsOutput, ProcessedTransactionCounts};
use solana_runtime::bank_forks::BankForks;
use solana_runtime::transaction_batch::TransactionBatch;
use solana_sdk::account::{Account, AccountSharedData, ReadableAccount, WritableAccount};
use solana_sdk::clock::{Clock, Epoch, Slot};
use solana_sdk::epoch_rewards::EpochRewards;
use solana_sdk::epoch_schedule::EpochSchedule;
use solana_sdk::feature_set::{self, FeatureSet};
use solana_sdk::fee::FeeStructure;
use solana_sdk::genesis_config::GenesisConfig;
use solana_sdk::instruction::InstructionError;
use solana_sdk::message::SanitizedMessage;
use solana_sdk::nonce::state::DurableNonce;
use solana_sdk::nonce::NONCED_TX_MARKER_IX_INDEX;
use solana_sdk::precompiles::get_precompiles;
use solana_sdk::rent::Rent;
use solana_sdk::rent_collector::RentCollector;
use solana_sdk::reserved_account_keys::ReservedAccountKeys;
use solana_sdk::signature::Signature;
use solana_sdk::sysvar::recent_blockhashes::{
    IntoIterSorted, IterItem, RecentBlockhashes, MAX_ENTRIES,
};
use solana_sdk::transaction::{
    SanitizedTransaction, SanitizedVersionedTransaction, TransactionError, VersionedTransaction,
};
use solana_sdk::transaction_context::TransactionAccount;
use solana_sdk::{native_loader, nonce, nonce_account, sysvar};
use solana_svm::account_loader::{
    CheckedTransactionDetails, LoadedTransaction, TransactionCheckResult,
};
use solana_svm::nonce_info::NonceInfo;
use solana_svm::runtime_config::RuntimeConfig;
use solana_svm::transaction_error_metrics::TransactionErrorMetrics;
use solana_svm::transaction_processing_callback::TransactionProcessingCallback;
use solana_svm::transaction_processing_result::TransactionProcessingResultExtensions;
use solana_svm::transaction_processor::{
    ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig,
    TransactionProcessingEnvironment,
};
use solana_timings::ExecuteTimings;
use std::borrow::Cow;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::c_int;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

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

    let txn_result = match execute_transaction_new(txn_context) {
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

#[derive(Default)]
struct MockAccountsDb {
    pub accounts: RwLock<HashMap<Pubkey, AccountSharedData>>,
}

struct DummyForkGraph {}
impl ForkGraph for DummyForkGraph {
    fn relationship(&self, _a: Slot, _b: Slot) -> BlockRelation {
        BlockRelation::Unknown
    }
}

impl TransactionProcessingCallback for MockAccountsDb {
    /* Mimics account_matches_owners from accounts-db/src/accounts_db.rs */
    fn account_matches_owners(&self, account: &Pubkey, owners: &[Pubkey]) -> Option<usize> {
        let accounts_db = self.accounts.read().unwrap();
        let cached_account = accounts_db.get(account);
        match cached_account {
            Some(account_shared_data) => {
                if account_shared_data.is_zero_lamport() {
                    return None;
                } else {
                    return owners
                        .iter()
                        .position(|entry| account_shared_data.owner() == entry);
                }
            }
            None => {
                return None;
            }
        };
    }

    /* Mimics do_load_with_populate_read_cache from accounts-db/src/accounts_db.rs (call ends up down here) */
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        let accounts_db = self.accounts.read().unwrap();
        let cached_account = accounts_db.get(pubkey);
        match cached_account {
            Some(account_shared_data) => {
                if account_shared_data.is_zero_lamport() {
                    return None;
                } else {
                    return Some(account_shared_data.clone());
                }
            }
            None => {
                return None;
            }
        }
    }

    fn add_builtin_account(&self, _name: &str, _program_id: &Pubkey) {
        let builtin_account = Account {
            lamports: 1,
            data: _name.as_bytes().to_vec(),
            owner: native_loader::id(),
            executable: true,
            rent_epoch: 0,
        };
        self.accounts
            .write()
            .unwrap()
            .insert(*_program_id, AccountSharedData::from(builtin_account));
    }
}

fn set_sysvar<Sysvar>(
    accounts_db: &MockAccountsDb,
    pubkey: &Pubkey,
    default_sysvar: &Sysvar,
    rent_for_compute_exempt_balance: &Rent,
    force_overwrite: bool, // This isn't a part of bank, but FD overwrites the sysvar account data for recent blockhashes
) where
    Sysvar: serde::Serialize,
{
    let mut accounts = accounts_db.accounts.write().unwrap();
    let existing_account = accounts.get_mut(pubkey);
    match existing_account {
        Some(account) => {
            // Update lamports to min rent exempt balance
            account.set_lamports(
                account
                    .lamports()
                    .max(rent_for_compute_exempt_balance.minimum_balance(account.data().len())),
            );
            if force_overwrite {
                let serialized_data = bincode::serialize(default_sysvar).unwrap();
                account.resize(serialized_data.len(), 0);
                account
                    .data_as_mut_slice()
                    .copy_from_slice(&serialized_data);
            }
        }
        None => {
            // Create new sysvar account
            let account = Account {
                lamports: 1,
                data: bincode::serialize(default_sysvar).unwrap(),
                owner: native_loader::id(),
                executable: false,
                rent_epoch: 0,
            };
            accounts.insert(*pubkey, account.into());
        }
    }
}

/* Copied from update_account from runtime/src/bank/recent_blockhashes_account.rs */
#[allow(deprecated)]
fn get_recent_blockhashes<'a, I>(recent_blockhash_iter: I) -> RecentBlockhashes
where
    I: IntoIterator<Item = IterItem<'a>>,
{
    let sorted = BinaryHeap::from_iter(recent_blockhash_iter);
    let sorted_iter = IntoIterSorted::new(sorted);
    let recent_blockhash_iter = sorted_iter.take(MAX_ENTRIES);
    recent_blockhash_iter.collect()
}

fn load_message_nonce_account(
    mock_accounts_db: &MockAccountsDb,
    message: &SanitizedMessage,
) -> Option<(NonceInfo, nonce::state::Data)> {
    let nonce_address = message.get_durable_nonce()?;
    let nonce_account = mock_accounts_db.get_account_shared_data(nonce_address)?;
    let nonce_data =
        nonce_account::verify_nonce_account(&nonce_account, message.recent_blockhash())?;

    let nonce_is_authorized = message
        .get_ix_signers(NONCED_TX_MARKER_IX_INDEX as usize)
        .any(|signer| signer == &nonce_data.authority);
    if !nonce_is_authorized {
        return None;
    }

    Some((NonceInfo::new(*nonce_address, nonce_account), nonce_data))
}

fn check_and_load_message_nonce_account(
    mock_accounts_db: &MockAccountsDb,
    message: &SanitizedMessage,
    next_durable_nonce: &DurableNonce,
) -> Option<(NonceInfo, nonce::state::Data)> {
    let nonce_is_advanceable = message.recent_blockhash() != next_durable_nonce.as_hash();
    if nonce_is_advanceable {
        load_message_nonce_account(mock_accounts_db, message)
    } else {
        None
    }
}

fn check_transaction_age(
    mock_accounts_db: &MockAccountsDb,
    tx: &SanitizedTransaction,
    max_age: usize,
    next_durable_nonce: &DurableNonce,
    hash_queue: &BlockhashQueue,
) -> TransactionCheckResult {
    let recent_blockhash = tx.message().recent_blockhash();
    if let Some(hash_info) = hash_queue.get_hash_info_if_valid(recent_blockhash, max_age) {
        Ok(CheckedTransactionDetails {
            nonce: None,
            lamports_per_signature: hash_info.lamports_per_signature(),
        })
    } else if let Some((nonce, nonce_data)) =
        check_and_load_message_nonce_account(mock_accounts_db, tx.message(), next_durable_nonce)
    {
        Ok(CheckedTransactionDetails {
            nonce: Some(nonce),
            lamports_per_signature: nonce_data.get_lamports_per_signature(),
        })
    } else {
        Err(TransactionError::BlockhashNotFound)
    }
}

#[allow(deprecated)]
fn execute_transaction_new(context: TxnContext) -> Option<TxnResult> {
    let fd_features = context
        .epoch_ctx
        .as_ref()
        .map(|ctx| ctx.features.clone().unwrap_or_default())
        .unwrap_or_default();

    let input_feature_set = Arc::new(FeatureSet::from(&fd_features));
    let fee_collector = Pubkey::new_unique();
    let slot = context.slot_ctx.as_ref().map(|ctx| ctx.slot).unwrap_or(10); // Arbitrary default > 0
    let mut input_blockhash_queue = context.blockhash_queue;
    let genesis_hash = if input_blockhash_queue.is_empty() {
        None
    } else {
        Some(Hash::new(input_blockhash_queue[0].as_slice()))
    };

    let transaction_processor = TransactionBatchProcessor::<DummyForkGraph>::new(
        slot,
        Epoch::default(),
        HashSet::<Pubkey>::default(),
    );

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

    /* Mock the accounts db with a hashmap and load builtins
    Mimics logic from bank.finish_init() */
    let mock_accounts_db = MockAccountsDb::default();
    for builtin in BUILTINS.iter() {
        if let Some(enable_feature_id) = builtin.enable_feature_id {
            if !input_feature_set.is_active(&enable_feature_id) {
                continue;
            }
        }
        transaction_processor.add_builtin(
            &mock_accounts_db,
            builtin.program_id,
            builtin.name,
            ProgramCacheEntry::new_builtin(0, builtin.name.len(), builtin.entrypoint),
        )
    }

    /* Add precompiles */
    for precompile in get_precompiles() {
        let should_add_precompile = precompile
            .feature
            .as_ref()
            .map(|feature_id| input_feature_set.is_active(feature_id))
            .unwrap_or(true);
        if should_add_precompile {
            // Empty data for precompiles
            mock_accounts_db.add_builtin_account("", &precompile.program_id);
        }
    }

    let mut program_cache = transaction_processor.program_cache.write().unwrap();
    let fork_graph = Arc::new(RwLock::new(DummyForkGraph {}));
    program_cache.latest_root_slot = slot;
    program_cache.environments.program_runtime_v1 = Arc::new(
        create_program_runtime_environment_v1(
            input_feature_set.as_ref(),
            &ComputeBudget::default(),
            false,
            false,
        )
        .unwrap(),
    );
    program_cache.fork_graph = Some(Arc::downgrade(&fork_graph));
    drop(program_cache);
    /* TODO: This will need to be uncommented when the v4 loader goes active
    program_cache.environments.program_runtime_v2 =
        Arc::new(create_program_runtime_environment_v2(
            &ComputeBudget::default(),
            false,
        ));
    */

    /* Store accounts and restore sysvar cache
    Sysvar account data is assumed to be fixed up and valid by either the fuzzer or through properly exported ledger transactions */
    for account in &context.tx.as_ref()?.message.as_ref()?.account_shared_data {
        let pubkey = Pubkey::new_from_array(account.address.clone().try_into().ok()?);
        // Skip accounts that have already been loaded in
        if mock_accounts_db.get_account_shared_data(&pubkey).is_some() {
            continue;
        }
        let account_data = AccountSharedData::from(account);
        mock_accounts_db
            .accounts
            .write()
            .unwrap()
            .insert(pubkey, account_data);
    }
    transaction_processor.fill_missing_sysvar_cache_entries(&mock_accounts_db);

    /* We need to use the proper sysvar cache rent for calculating the rent exempt balance */
    let rent_for_exempt_balance = match transaction_processor.sysvar_cache().get_rent() {
        Ok(rent) => rent.as_ref().clone(),
        Err(_) => Rent::default(),
    };

    /* Set sysvar accounts */
    set_sysvar(
        &mock_accounts_db,
        &sysvar::rent::id(),
        &Rent::default(),
        &rent_for_exempt_balance,
        false,
    );
    set_sysvar(
        &mock_accounts_db,
        &sysvar::clock::id(),
        &Clock {
            slot: slot,
            leader_schedule_epoch: 1,
            ..Clock::default()
        },
        &rent_for_exempt_balance,
        false,
    );
    set_sysvar(
        &mock_accounts_db,
        &sysvar::epoch_schedule::id(),
        &EpochSchedule::default(),
        &rent_for_exempt_balance,
        false,
    );
    if input_feature_set.is_active(&feature_set::enable_partitioned_epoch_reward::id()) {
        set_sysvar(
            &mock_accounts_db,
            &sysvar::epoch_rewards::id(),
            &EpochRewards {
                active: true,
                ..EpochRewards::default()
            },
            &rent_for_exempt_balance,
            false,
        );
    }

    /* Get lamports per signature from recent blockhashes if it exists */
    let mut lamports_per_signature = 5000_u64; // Default lamports per signature
    if let Ok(recent_blockhashes) = transaction_processor
        .sysvar_cache()
        .get_recent_blockhashes()
    {
        if let Some(hash) = recent_blockhashes.first() {
            lamports_per_signature = hash.fee_calculator.lamports_per_signature;
        }
    }

    /* Register blockhashes into the queue */
    let mut blockhash_queue = BlockhashQueue::default();
    for blockhash in input_blockhash_queue.iter_mut() {
        let hash = Hash::new_from_array(std::mem::take(blockhash).try_into().unwrap());
        blockhash_queue.register_hash(&hash, lamports_per_signature)
    }

    /* Set recent blockhashes from blockhash queue */
    let recent_blockhashes = get_recent_blockhashes(blockhash_queue.get_recent_blockhashes());
    set_sysvar(
        &mock_accounts_db,
        &sysvar::recent_blockhashes::id(),
        &recent_blockhashes,
        &rent_for_exempt_balance,
        true,
    );

    /* Store defaults in sysvar cache */
    transaction_processor.fill_missing_sysvar_cache_entries(&mock_accounts_db);

    /* Start building the transaction message */
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
    let mut reserved_account_keys = ReservedAccountKeys::default();
    reserved_account_keys.update_active_set(&input_feature_set);
    let sanitized_transaction = match SanitizedTransaction::try_new(
        sanitized_versioned_transaction,
        message_hash,
        context.tx?.is_simple_vote_tx,
        mock_loader,
        &reserved_account_keys.active,
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
    let pre_result = sanitized_transaction.verify_precompiles(&input_feature_set);
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

    let check_results = check_transaction_age(
        &mock_accounts_db,
        &transactions[0],
        context.max_age as usize,
        &DurableNonce::from_blockhash(&blockhash_queue.last_hash()),
        &blockhash_queue,
    );

    let recording_config = ExecutionRecordingConfig {
        enable_cpi_recording: false,
        enable_log_recording: true,
        enable_return_data_recording: true,
    };

    let configs = TransactionProcessingConfig {
        account_overrides: None,
        compute_budget: None,
        log_messages_bytes_limit: None,
        limit_to_load_programs: true,
        recording_config,
        transaction_account_lock_limit: None,
        check_program_modification_slot: false,
    };

    let genesis_config = GenesisConfig {
        creation_time: 0,
        rent: transaction_processor
            .get_sysvar_cache_for_tests()
            .get_rent()
            .unwrap()
            .as_ref()
            .clone(),
        ..GenesisConfig::default()
    };

    let rent_collector = RentCollector {
        epoch: transaction_processor
            .get_sysvar_cache_for_tests()
            .get_epoch_schedule()
            .unwrap()
            .get_epoch(slot),
        epoch_schedule: transaction_processor
            .get_sysvar_cache_for_tests()
            .get_epoch_schedule()
            .unwrap()
            .as_ref()
            .clone(),
        slots_per_year: genesis_config.slots_per_year(),
        rent: transaction_processor
            .get_sysvar_cache_for_tests()
            .get_rent()
            .unwrap()
            .as_ref()
            .clone(),
    };

    let fee_structure = FeeStructure::default();
    let environment = TransactionProcessingEnvironment {
        blockhash: blockhash_queue.last_hash(),
        epoch_total_stake: None,
        epoch_vote_accounts: None,
        feature_set: Arc::clone(&input_feature_set),
        fee_structure: Some(&fee_structure),
        lamports_per_signature,
        rent_collector: Some(&rent_collector),
    };
    let sanitized_results = transaction_processor.load_and_execute_sanitized_transactions(
        &mock_accounts_db,
        &transactions,
        vec![check_results],
        &environment,
        &configs,
    );

    let result = LoadAndExecuteTransactionsOutput {
        processing_results: sanitized_results.processing_results,
        processed_counts: ProcessedTransactionCounts::default(),
    };

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
                let account_data = mock_accounts_db.get_account_shared_data(
                    &Pubkey::new_from_array(account.address.clone().try_into().unwrap()),
                );
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
