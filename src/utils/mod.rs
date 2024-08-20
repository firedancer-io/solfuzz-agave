pub mod vm;
use crate::proto;
use crate::proto::AcctState;
use lazy_static::lazy_static;
use solana_program::pubkey::Pubkey;
use solana_sdk::account::{AccountSharedData, WritableAccount};
use solana_sdk::feature_set::{FeatureSet, FEATURE_NAMES};
use std::collections::HashMap;

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
    static ref INDEXED_FEATURES: HashMap<u64, Pubkey> = {
        FEATURE_NAMES
            .iter()
            .map(|(pubkey, _)| (feature_u64(pubkey), *pubkey))
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
        account_data.set_rent_epoch(input.rent_epoch);

        account_data
    }
}

/* Adapted from  https://github.com/firedancer-io/firedancer/blob/38c85a069effb2186524ad9bd76a639183fd712a/src/ballet/murmur3/fd_murmur3.h#L52 */
pub const fn pchash_inverse(hash: u32) -> u32 {
    let mut x = hash;
    x ^= x >> 16;
    x = x.wrapping_mul(0x7ed1b41d);
    x ^= (x >> 13) ^ (x >> 26);
    x = x.wrapping_mul(0xa5cb9243);
    x ^= x >> 16;
    x ^= 8;
    x = x.wrapping_sub(0xe6546b64);
    x = x.wrapping_mul(0xcccccccd);
    x = x.rotate_right(13);
    x = x.wrapping_sub(0xe6546b64);
    x = x.wrapping_mul(0xcccccccd);
    x = x.rotate_right(13);
    x = x.wrapping_mul(0x56ed309b);
    x = x.rotate_right(15);
    x = x.wrapping_mul(0xdee13bb1);
    x
}