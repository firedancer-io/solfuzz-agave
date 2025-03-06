# thread-scoped

[![travis-badge][]][travis] [![release-badge][]][cargo] [![docs-badge][]][docs] [![license-badge][]][license]

A `std::thread::spawn()` that can access its current scope.
Stable fork of the deprecated `std::thread::scoped()`


## Memory Unsafety

This interface is inherently unsafe if the `JoinGuard` is allowed to leak without being dropped.
See [rust-lang/rust#24292](https://github.com/rust-lang/rust/issues/24292) for more details.


## Alternatives

This crate is only provided as a fallback mirror for legacy dependency on the
deprecated `libstd` interface. Using a modern and safe API instead is recommended:

- [crossbeam::scope](https://github.com/crossbeam-rs/crossbeam)


[travis-badge]: https://img.shields.io/travis/arcnmx/thread-scoped-rs/master.svg?style=flat-square
[travis]: https://travis-ci.org/arcnmx/thread-scoped-rs
[release-badge]: https://img.shields.io/crates/v/thread_scoped.svg?style=flat-square
[cargo]: https://crates.io/crates/thread-scoped
[docs-badge]: https://img.shields.io/badge/API-docs-blue.svg?style=flat-square
[docs]: http://arcnmx.github.io/thread-scoped-rs/thread_scoped/
[license-badge]: https://img.shields.io/badge/license-MIT-lightgray.svg?style=flat-square
[license]: https://github.com/arcnmx/thread-scoped-rs/blob/master/COPYING
