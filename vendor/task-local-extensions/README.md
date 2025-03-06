# task-local-extensions

Provides a type-safe task-local container for arbitrary data keyed by types.

[![Crates.io](https://img.shields.io/crates/v/task-local-extensions.svg)](https://crates.io/crates/task-local-extensions)
[![Docs.rs](https://docs.rs/task-local-extensions/badge.svg)](https://docs.rs/task-local-extensions)
[![CI](https://github.com/TrueLayer/task-local-extensions/workflows/CI/badge.svg)](https://github.com/TrueLayer/task-local-extensions/actions)
[![Coverage Status](https://coveralls.io/repos/github/TrueLayer/task-local-extensions/badge.svg?branch=main&t=DdH5KB)](https://coveralls.io/github/TrueLayer/task-local-extensions?branch=main)

## How to install

Add `task-local-extensions` to your dependencies

```toml
[dependencies]
# ...
task-local-extensions = "0.1.0"
```

## Usage

[`Extensions`](https://docs.rs/task-local-extensions/latest/task_local_extensions/struct.Extensions.html)
is a container that can store up to one value of each type, so you can insert and retrive values by
their type:

```rust
use task_local_extensions::Extensions;

let a: i64 = 3;
let mut ext = Extensions::new();
ext.insert(a);
assert_eq!(ext.get::<i64>(), Some(&3));
```

The crate also provides [`with_extensions`](https://docs.rs/task-local-extensions/latest/task_local_extensions/fn.with_extensions.html)
so you set an `Extensions` instance while running a given task:

```rust
use task_local_extensions::{get_local_item, set_local_item, with_extensions, Extensions};

async fn my_task() {
  let a: i64 = get_local_item().await.unwrap(0);
  let msg = format!("The value of a is: {}", a);
  set_local_item(msg).await;
}

let a: i64 = 3;
let (out_ext, _) = with_extensions(Extensions::new().with(a), my_task()).await;
let msg = out_ext.get::<String>().unwrap();
assert_eq!(msg.as_str(), "The value of a is: 3");
```

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
</sub>
