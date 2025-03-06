use std::hash::Hash;

/// A unique identifier that can identify resources used by a transaction.
pub trait ResourceKey: Copy + Eq + Hash {}

/// Type of access for a specific resource key.
pub enum AccessKind {
    Read,
    Write,
}

impl<T: Copy + Eq + Hash> ResourceKey for T {}
