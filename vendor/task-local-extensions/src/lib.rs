//! A type map for storing data of arbritrary type.
//!
//! # Extensions
//! [`Extensions`] is a container that can store up to one value of each type, so you can insert and retrive values by
//! their type:
//!
//! ```
//! use task_local_extensions::Extensions;
//!
//! let a: i64 = 3;
//! let mut ext = Extensions::new();
//! extensions.insert(a);
//! assert_eq!(ext.get::<i64>(), Some(&3));
//! ```
//!
//! # Task Local Extensions
//! The crate also provides [`with_extensions`] so you set an [`Extensions`] instance while running a given task:
//!
//! ```
//! use task_local_extensions::{get_local_item, set_local_item, with_extensions, Extensions};
//!
//! async fn my_task() {
//!   let a: i64 = get_local_item().await.unwrap(0);
//!   let msg = format!("The value of a is: {}", a);
//!   set_local_item(msg).await;
//! }
//!
//! let a: i64 = 3;
//! let (out_ext, _) = with_extensions(Extensions::new().with(a), my_task()).await;
//! let msg = out_ext.get::<String>().unwrap();
//! assert_eq!(msg.as_str(), "The value of a is: 3");
//! ```

mod extensions;
mod task_local;

pub use extensions::*;
pub use task_local::*;
