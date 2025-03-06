//! [`AssocExt`] is a trait extension that allows you to work with [`Vec<(K, V)>`][Vec] as if it
//! were a map.
//! It provides APIs for querying, adding, and removing key-value pairs, as well as an [`Entry`]
//! API.
//! It places no constraints on the keys other than [`PartialEq`].
//!
//! ```rust
//! use assoc::AssocExt;
//!
//! #[derive(PartialEq, Debug)]
//! enum MyKey {
//!     A,
//!     B,
//!     C,
//! }
//!
//! let mut map = vec![(MyKey::A, 1), (MyKey::B, 2)];
//! map.entry(MyKey::C).or_insert(3);
//! assert_eq!(map.get(&MyKey::C), Some(&3));
//! map.entry(MyKey::A).and_modify(|e| *e += 1).or_insert(9);
//! assert_eq!(map.get(&MyKey::A), Some(&2));
//! ```
//!
//! ## Why?
//!
//! [`std::collections`] offers two maps: [`HashMap`] and [`BTreeMap`].
//! `HashMap` requires that its keys implement [`Hash`] and [`Eq`] while `BTreeMap` requires that
//! its keys implement [`Ord`] and [`Eq`].
//! `Hash` and `Ord` enable efficient implementations of mapping data structures; however, they are not
//! necessary for general mapping data structures.
//! `std::collections` falls short when working with keys that cannot implement `Hash` or `Ord`.
//!
//! For example, the following snippet fails to compile because `Hash` is not implemented for `MyKey`:
//!
//! ```compile_fail
//! use std::collections::HashMap;
//!
//! #[derive(PartialEq, Eq, Debug)]
//! enum MyKey {
//!     A,
//!     B,
//!     C,
//! }
//!
//! let map = vec![(MyKey::A, 1), (MyKey::B, 2)]
//!     .into_iter()
//!     .collect::<HashMap<MyKey, u64>>();
//! ```
//!
//! ## Performance
//!
//! Using a `Vec` as a general mapping data structure through `AssocExt` comes with the drawback of
//! inefficient lookups.
//! Since `AssocExt` cannot rely on keys being hashable or comparable, all operations that require
//! lookups invoke a linear search through the underlying vector.
//! Querying for a key `k` invokes `O(N)` equality comparisons with `k`.
//!
//! Workflows that involve frequent resizing should consider using `Vec` with `AssocExt` as it
//! takes advantage of spatial locality during reallocation.
//! Empirically, `Vec`s are faster than `HashMap`s and `BTreeMap`s when performing operations such
//! as growing the maps to around 50 elements.
//! For larger maps, the cost of linear searches begins to dominate.
//! Unsurprisingly, `Vec` has a lower memory footprint than `HashMap` and `BTreeMap`.
//!
//! The `Entry` API eliminates the need for multiple sequential lookups (e.g. check for existence
//! of a key, then add the key if it doesn't exist).
//! Invoking [`AssocExt::entry`] requires one initial linear search, then constant time access for in-place
//! mutation thereafter.
//!
//! ## `PartialEq` vs `Eq`
//!
//! Strictly speaking, a map's keys should implement `Eq`, which is why this crate provides a
//! [`AssocStrictExt`] as well.
//! This trait extension behaves like `AssocExt` but requires `K: Eq`.
//!
//! This is a notable distinction when working with keys containing floating point values. Since
//! `f32::NAN != f32::NAN`, maps cannot update existing entries that have keys containing
//! `f32::NAN`:
//!
//! ```rust
//! use assoc::AssocExt;
//!
//! let mut v = vec![(1.0, "a")];
//! v.entry(f32::NAN).or_insert("b");
//! v.entry(f32::NAN).or_insert("c");
//! assert_eq!(format!("{:?}", v), r#"[(1.0, "a"), (NaN, "b"), (NaN, "c")]"#);
//! ```
//!
//! Using floating points as keys in a map is often a code smell, but for use cases that don't run
//! into NaNs `AssocExt` is a great fit.
//!
//! [`HashMap`]: std::collections::HashMap
//! [`BTreeMap`]: std::collections::BTreeMap
//! [`Entry`]: vec::Entry
pub mod vec;

pub use vec::{AssocExt, AssocStrictExt};
