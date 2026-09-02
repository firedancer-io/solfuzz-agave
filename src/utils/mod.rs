use solana_accounts_db::accounts::Accounts;
use solana_accounts_db::accounts_db::{AccountsDb, AccountsDbConfig};
use solana_accounts_db::accounts_index::{AccountsIndexConfig, IndexLimit};
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

pub fn create_accounts_db(paths: Vec<PathBuf>) -> Accounts {
    let index = Some(AccountsIndexConfig {
        bins: Some(2),
        num_flush_threads: Some(NonZeroUsize::new(1).unwrap()),
        index_limit: IndexLimit::InMemOnly,
        ..AccountsIndexConfig::default()
    });
    let accounts_db_config = AccountsDbConfig {
        index,
        skip_initial_hash_calc: true,
        num_background_threads: Some(NonZeroUsize::new(1).unwrap()),
        num_foreground_threads: Some(NonZeroUsize::new(1).unwrap()),
        exhaustively_verify_refcounts: false,
        read_cache_num_shards: Some(2),
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
