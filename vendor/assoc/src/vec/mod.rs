//! See the [module level documentation for an overview](crate).
mod entry;
mod ext;

pub use entry::{Entry, OccupiedEntry, VacantEntry};
pub use ext::{AssocExt, AssocStrictExt};
