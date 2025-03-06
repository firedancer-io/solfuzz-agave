//! A small, cross-platform crate for creating symlinks.
//!
#![cfg_attr(not(any(target_os = "redox", unix, windows)), doc = "**This platform is not Unix, Windows or Redox; symlinks are not available.**")]
//!
//! For efficiency, you should prefer to use `symlink_file` or `symlink_dir`—whichever is
//! appropriate—rather than `symlink_auto`

// It’s generally nicer to produce an empty crate on unsupported platforms than to explode.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(windows)]
#[path = "windows/mod.rs"]
mod internal;

#[cfg(any(target_os = "redox", unix))]
mod internal {
    pub use std::fs::remove_file as remove_symlink_dir;
    pub use std::fs::remove_file as remove_symlink_auto;
    // Note that this symlink function takes src and dst as &Path rather than as impl AsRef<Path>.
    // I don’t know why that is, but I think we’ll go with impl AsRef<Path> in our public
    // functions. Because of this disparity of signature, when I say that things are equivalent to
    // calling std::os::unix::fs::symlink on Unix, you can see that I’m not being *quite* rigorous.
    pub use std::os::unix::fs::{symlink as symlink_auto,
                                symlink as symlink_file,
                                symlink as symlink_dir};
}

/// Create a symlink (non-preferred way).
///
/// On Windows, file and directory symlinks are created by distinct methods; to cope with that,
/// this function checks whether the destination is a file or a folder and creates the appropriate
/// type of symlink based on that result. Therefore, if the destination does not exist or if you do
/// not have permission to fetch its metadata, this will return an error on Windows.
///
/// On Unix platforms there is no distinction, so this isn’t magic: it’s precisely equivalent to
/// calling `std::os::unix::fs::symlink`.
///
/// # A note on using this function
///
/// Because this is slightly less efficient and more hazardous on Windows, you should prefer to use
/// [`symlink_file`](fn.symlink_file.html) or [`symlink_dir`](fn.symlink_dir.html) instead. Only
/// use this if you don’t know or care whether the destination is a file or a directory (but even
/// then, you do need to know that it exists).
///
/// # Errors
///
/// An error will be returned if the symlink cannot be created, or—on Windows—if the destination
/// does not exist or cannot be read.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn symlink_auto<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
    internal::symlink_auto(src.as_ref(), dst.as_ref())
}

/// Create a symlink to a file.
///
/// On Windows, this is equivalent to `std::os::windows::fs::symlink_file`. If you call it with a
/// directory as the destination, TODO CONSEQUENCES.
///
/// On Unix, this is equivalent to `std::os::unix::fs::symlink`. If you call it with a directory as
/// the destination, nothing bad will happen, but you’re ruining your cross-platform technique and
/// ruining the point of this crate, so please don’t.
///
/// # Errors
///
/// An error will be returned if the symlink cannot be created.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn symlink_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
    internal::symlink_file(src.as_ref(), dst.as_ref())
}

/// Create a symlink to a directory.
///
/// On Windows, this is equivalent to `std::os::windows::fs::symlink_dir`. If you call it with a
/// directory as the destination, TODO CONSEQUENCES.
///
/// On Unix, this is equivalent to `std::os::unix::fs::symlink`. If you call it with a directory as
/// the destination, nothing bad will happen, but you’re ruining your cross-platform technique and
/// ruining the point of this crate, so please don’t.
///
/// # Errors
///
/// An error will be returned if the symlink cannot be created.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
    internal::symlink_dir(src.as_ref(), dst.as_ref())
}

/// Remove a symlink (non-preferred way).
///
/// This inspects the path metadata to remove the symlink as a file or directory, whichever is
/// necessary.
///
/// # A note on using this function
///
/// Because this is slightly less efficient on Windows, you should prefer to use
/// [`remove_symlink_file`](fn.remove_symlink_file.html) or
/// [`remove_symlink_dir`](fn.remove_symlink_dir.html) instead. Only use this if you don’t know or
/// care whether the destination is a file or a directory (but even then, you do need to know that
/// it exists).
///
/// # Errors
///
/// An error will be returned if the symlink cannot be removed.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn remove_symlink_auto<P: AsRef<Path>>(path: P) -> io::Result<()> {
    internal::remove_symlink_auto(path)
}

/// Remove a directory symlink.
///
/// On Windows, this corresponds to `std::fs::remove_dir`.
///
/// On Unix, this corresponds to `std::fs::remove_file`.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn remove_symlink_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    internal::remove_symlink_dir(path)
}

/// Remove a file symlink.
///
/// This just calls `std::fs::remove_file`, but the function is provided here to correspond to
/// `remove_symlink_dir`.
///
/// On Unix, this corresponds to `std::fs::remove_file`.
#[cfg(any(target_os = "redox", unix, windows))]
#[inline]
pub fn remove_symlink_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::remove_file(path)
}
