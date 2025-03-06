use crate::TransactionId;

/// A top-level ID that should contain the unique `Id`, but can be priority ordered.
pub trait TopLevelId<Id: TransactionId>: Eq + PartialEq + Ord + PartialOrd {
    fn id(&self) -> Id;
}
