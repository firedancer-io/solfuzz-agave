use std::hash::Hash;

/// A unique identifier that can be used both to identify a transaction.
pub trait TransactionId: Copy + Eq + Hash {}

impl<T: Copy + Eq + Hash> TransactionId for T {}
