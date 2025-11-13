use crate::{context_generated, utils::INDEXED_FEATURES};
use agave_feature_set::FeatureSet;

/* TODO: Split these conversions out into their own utility files */
impl<'a> From<&context_generated::FeatureSet<'a>> for FeatureSet {
    fn from(input: &context_generated::FeatureSet<'a>) -> Self {
        let mut feature_set = FeatureSet::default();
        for id in input.features().unwrap_or_default() {
            if let Some(pubkey) = INDEXED_FEATURES.get(&id) {
                feature_set.activate(pubkey, 0);
            }
        }
        feature_set
    }
}
