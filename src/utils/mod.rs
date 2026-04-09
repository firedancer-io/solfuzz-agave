pub mod err_map;
pub mod fd_hash;
pub mod program;
pub mod vm;
use agave_feature_set::{FeatureSet, FEATURE_NAMES};
use ahash::AHashMap;
use lazy_static::lazy_static;
use protosol::protos;
use protosol::protos::AcctState;
use solana_account::{AccountSharedData, ReadableAccount};
use solana_accounts_db::accounts::Accounts;
use solana_accounts_db::accounts_db::{AccountsDb, AccountsDbConfig};
use solana_accounts_db::accounts_file::StorageAccess;
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimit};
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub const fn feature_u64(feature: &Pubkey) -> u64 {
    let feature_id = feature.to_bytes();
    feature_id[0] as u64
        | (feature_id[1] as u64) << 8
        | (feature_id[2] as u64) << 16
        | (feature_id[3] as u64) << 24
        | (feature_id[4] as u64) << 32
        | (feature_id[5] as u64) << 40
        | (feature_id[6] as u64) << 48
        | (feature_id[7] as u64) << 56
}

lazy_static! {
    static ref INDEXED_FEATURES: AHashMap<u64, Pubkey> = {
        FEATURE_NAMES
            .keys()
            .map(|pubkey| (feature_u64(pubkey), *pubkey))
            .collect()
    };
}

pub fn feature_set_from_protos(input: &protos::FeatureSet) -> FeatureSet {
    let mut feature_set = FeatureSet::default();
    for id in &input.features {
        if let Some(pubkey) = INDEXED_FEATURES.get(id) {
            feature_set.activate(pubkey, 0);
        }
    }
    feature_set
}

pub fn restore_blockhash_queue(entries: &[protos::BlockhashQueueEntry]) -> BlockhashQueue {
    let mut blockhash_queue = BlockhashQueue::default();
    entries.iter().for_each(|entry| {
        let hash = Hash::new_from_array(entry.blockhash.clone().try_into().unwrap());
        blockhash_queue.register_hash(&hash, entry.lamports_per_signature);
    });
    blockhash_queue
}

pub fn create_accounts_db(paths: Vec<PathBuf>) -> Accounts {
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit: IndexLimit::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = AccountsDbConfig {
        index,
        storage_access: StorageAccess::File,
        skip_initial_hash_calc: true,
        ..AccountsDbConfig::default()
    };
    let accounts_db = AccountsDb::new_with_config(
        paths,
        accounts_db_config,
        None,
        Arc::new(AtomicBool::new(false)),
    );
    Accounts::new(Arc::new(accounts_db))
}

pub fn deserialize_accounts(acct_states: &[AcctState]) -> Vec<(Pubkey, AccountSharedData)> {
    acct_states
        .iter()
        .filter(|account| account.lamports > 0)
        .map(|account| {
            let pubkey = Pubkey::new_from_array(account.address.clone().try_into().unwrap());
            let account_data = AccountSharedData::from(account);
            (pubkey, account_data)
        })
        .collect()
}

pub fn compute_accounts_data_size(accounts: &[(Pubkey, AccountSharedData)]) -> u64 {
    accounts
        .iter()
        .map(|(_, account)| account.data().len() as u64)
        .sum()
}
