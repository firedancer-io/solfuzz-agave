#![deny(missing_docs)]

//! A stable version of `std::thread::scoped`
//!
//! ## Warning
//!
//! This is inherently unsafe if the `JoinGuard` is allowed to leak without being dropped.
//! See [rust-lang/rust#24292](https://github.com/rust-lang/rust/issues/24292) for more details.

use std::marker::PhantomData;
use std::thread::{spawn, JoinHandle, Thread};
use std::mem::{transmute, forget};

/// A RAII guard for that joins a scoped thread upon drop
///
/// # Panics
///
/// `JoinGuard` will panic on join or drop if its owned thread panics
#[must_use = "thread will be immediately joined if `JoinGuard` is not used"]
pub struct JoinGuard<'a, T: Send + 'a> {
    inner: Option<JoinHandle<BoxedThing>>,
    _marker: PhantomData<&'a T>,
}

unsafe impl<'a, T: Send + 'a> Sync for JoinGuard<'a, T> {}

impl<'a, T: Send + 'a> JoinGuard<'a, T> {
    /// Provides the backing `Thread` object
    pub fn thread(&self) -> &Thread {
        &self.inner.as_ref().unwrap().thread()
    }

    /// Joins the guarded thread and returns its result
    ///
    /// # Panics
    ///
    /// `join()` will panic if the owned thread panics
    pub fn join(mut self) -> T {
        match self.inner.take().unwrap().join() {
            Ok(res) => unsafe { *res.into_inner() },
            Err(_) => panic!("child thread {:?} panicked", self.thread()),
        }
    }
}

/// Detaches a child thread from its guard
pub trait ScopedDetach {
    /// Detaches a child thread from its guard
    ///
    /// Note: Only valid for the 'static lifetime
    fn detach(self);
}

impl<T: Send + 'static> ScopedDetach for JoinGuard<'static, T> {
    fn detach(mut self) {
        let _ = self.inner.take();
    }
}

impl<'a, T: Send + 'a> Drop for JoinGuard<'a, T> {
    fn drop(&mut self) {
        self.inner.take().map(|v| if v.join().is_err() {
            panic!("child thread {:?} panicked", self.thread());
        });
    }
}

/// Spawns a new scoped thread
pub unsafe fn scoped<'a, T, F>(f: F) -> JoinGuard<'a, T> where
    T: Send + 'a, F: FnOnce() -> T, F: Send + 'a
{
    let f = BoxedThing::new(f);

    JoinGuard {
        inner: Some(spawn(move ||
            BoxedThing::new(f.into_inner::<F>()())
        )),
        _marker: PhantomData,
    }
}

struct BoxedThing(usize);
impl BoxedThing {
    fn new<T>(v: T) -> Self {
        let mut b = Box::new(v);
        let b_ptr = &mut *b as *mut _ as usize;
        forget(b);
        BoxedThing(b_ptr)
    }

    unsafe fn into_inner<T>(self) -> Box<T> {
        transmute(self.0 as *mut T)
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;
    use super::scoped;

    #[test]
    fn test_scoped_stack() {
        unsafe {
            let mut a = 5;
            scoped(|| {
                sleep(Duration::from_millis(100));
                a = 2;
            }).join();
            assert_eq!(a, 2);
        }
    }

    #[test]
    fn test_join_success() {
        unsafe {
            assert!(scoped(move|| -> String {
                "Success!".to_string()
            }).join() == "Success!");
        }
    }

    #[test]
    fn test_scoped_success() {
        unsafe {
            let res = scoped(move|| -> String {
                "Success!".to_string()
            }).join();
            assert!(res == "Success!");
        }
    }

    #[test]
    #[should_panic]
    fn test_scoped_panic() {
        unsafe {
            scoped(|| panic!()).join();
        }
    }

    #[test]
    #[should_panic]
    fn test_scoped_implicit_panic() {
        unsafe {
            let _ = scoped(|| panic!());
        }
    }
}
