use crate::{context_generated, utils::INDEXED_FEATURES};
use agave_feature_set::FeatureSet;

pub fn feature_set_from_fbs(input: &context_generated::FeatureSet<'_>) -> FeatureSet {
    let mut feature_set = FeatureSet::default();
    for id in input.features().unwrap_or_default() {
        if let Some(pubkey) = INDEXED_FEATURES.get(&id) {
            feature_set.activate(pubkey, 0);
        }
    }
    feature_set
}
