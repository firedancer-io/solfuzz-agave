//! Temporarily redirect stdout/stderr.
//!
//! For example, one can temporarily throw away stdout output:
//!
//! ```
//! use gag::Gag;
//! println!("Hello world!");
//! {
//!     let print_gag = Gag::stdout().unwrap();
//!     println!("No one will see this!");
//!     println!("Or this!");
//! }
//! println!("But they will see this!");
//! ```
//!
//! You can also temporarily un-gag by dropping the gag:
//!
//! ```
//! use gag::Gag;
//! let mut print_gag = Gag::stdout().unwrap();
//! println!("No one will see this!");
//! if true {
//!     drop(print_gag);
//!     println!("They will see this...");
//!     print_gag = Gag::stdout().unwrap();
//!     println!("Not this...");
//! }
//! println!("Nor this.");
//! ```
//!
//! However, you can't open multiple Gags/Redirects/Holds for the same output at once:
//!
//! ```
//! use gag::Gag;
//! // Multiple stdout gags
//! let gag_a = Gag::stdout().unwrap();
//! let gag_b_result = Gag::stdout();
//! assert!(gag_b_result.is_err());
//! assert_eq!(gag_b_result.err().expect("Expected an error").kind(),
//!            std::io::ErrorKind::AlreadyExists);
//!
//! // However, you can still gag stderr:
//! let gag_c = Gag::stderr().unwrap();
//! ```
//!
//! If you don't want to throw away stdout, you can write it to a file:
//!
//! ```
//! # extern crate dirs;
//! use std::fs::OpenOptions;
//! use std::io::{Read, Write, Seek, SeekFrom};
//! use gag::Redirect;
//! use dirs::data_local_dir;
//!
//! fn get_temp_filepath() -> String {
//!     #[cfg(windows)]
//!     return data_local_dir()
//!         .unwrap()
//!         .join("Temp")
//!         .join("my_log.log")
//!         .to_string_lossy()
//!         .into();
//!
//!     #[cfg(unix)]
//!     return "/tmp/my_log.log".into();
//! }
//!
//! println!("Displayed");
//!
//! // Open a log
//! let log = OpenOptions::new()
//!     .truncate(true)
//!     .read(true)
//!     .create(true)
//!     .write(true)
//!     .open(get_temp_filepath())
//!     .unwrap();
//!
//! let print_redirect = Redirect::stdout(log).unwrap();
//! println!("Hidden");
//!
//! // Extract redirect
//! let mut log = print_redirect.into_inner();
//! println!("Displayed");
//!
//! let mut buf = String::new();
//! log.seek(SeekFrom::Start(0)).unwrap();
//! log.read_to_string(&mut buf).unwrap();
//! assert_eq!(&buf[..], "Hidden\n");
//!
//! ```
//!
//! Alternatively, you can buffer stdout to a temporary file. On linux 3.11+, this file is
//! guarenteed to be stored in-memory.
//!
//! ```
//! use std::io::Read;
//! use gag::BufferRedirect;
//!
//! let mut buf = BufferRedirect::stdout().unwrap();
//! println!("Hello world!");
//!
//! let mut output = String::new();
//! buf.read_to_string(&mut output).unwrap();
//!
//! assert_eq!(&output[..], "Hello world!\n");
//! ```
//!
//! Finally, if you just want to temporarily hold std output, you can use `Hold` to hold the output
//! until dropped:
//!
//! ```
//! use gag::Hold;
//!
//! let hold = Hold::stdout().unwrap();
//! println!("first");
//! println!("second");
//! drop(hold); // printing happens here!
//! ```
extern crate filedescriptor;
extern crate tempfile;

mod buffer;
mod gag;
mod hold;
mod redirect;

pub use buffer::{Buffer, BufferRedirect};
pub use gag::Gag;
pub use hold::Hold;
pub use redirect::{Redirect, RedirectError};
