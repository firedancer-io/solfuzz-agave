pub mod err_map;
pub mod fd_hash;
pub mod program;
pub mod vm;
use crate::proto;
use crate::proto::AcctState;
use agave_feature_set::{FeatureSet, FEATURE_NAMES};
use ahash::AHashMap;
use lazy_static::lazy_static;
use solana_account::{AccountSharedData, WritableAccount};
use solana_pubkey::Pubkey;
use solana_svm::rent_calculator::RENT_EXEMPT_RENT_EPOCH;

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

impl From<&proto::FeatureSet> for FeatureSet {
    fn from(input: &proto::FeatureSet) -> Self {
        let mut feature_set = FeatureSet::default();
        for id in &input.features {
            if let Some(pubkey) = INDEXED_FEATURES.get(id) {
                feature_set.activate(pubkey, 0);
            }
        }
        feature_set
    }
}

impl From<&AcctState> for AccountSharedData {
    fn from(input: &AcctState) -> Self {
        // TODO: Can I move?
        let mut account_data = AccountSharedData::default();
        account_data.set_lamports(input.lamports);
        account_data.set_data_from_slice(input.data.as_slice());
        account_data.set_owner(Pubkey::new_from_array(
            input.owner.clone().try_into().unwrap(),
        ));
        account_data.set_executable(input.executable);
        account_data.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);

        account_data
    }
}
