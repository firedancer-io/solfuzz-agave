// Implementation is based on
// - https://github.com/http-rs/http-types/blob/master/src/extensions.rs

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;

/// `Extensions` is a type map: values are stored and retrieved using their
/// [`TypeId`](https://doc.rust-lang.org/std/any/struct.TypeId.html).
///
/// This allows storing arbitrary data that implements `Sync + Send + 'static`. This is
/// useful when you need to share data between different middlewares in the middleware chain
/// or make some values available from the handler to middlewares
/// on the outgoing path (e.g. error class).
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    /// Create an empty `Extensions`.
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }

    /// Insert a value ino this [`Extensions`], returning self instead of any pre-inserted values.
    ///
    /// This is useful for any builder style patterns
    ///
    /// ```
    /// # use task_local_extensions::Extensions;
    /// let ext = Extensions::new().with(true).with(5_i32);
    /// assert_eq!(ext.get(), Some(&true));
    /// assert_eq!(ext.get(), Some(&5_i32));
    /// ```
    pub fn with<T: Send + Sync + 'static>(mut self, val: T) -> Self {
        self.insert(val);
        self
    }

    /// Removes the values from `other` and inserts them into `self`.
    pub fn append(&mut self, other: &mut Self) {
        self.map.extend(other.map.drain())
    }

    /// Insert a value into this `Extensions`.
    ///
    /// If a value of this type already exists, it will be returned.
    pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        self.map
            .insert(TypeId::of::<T>(), Box::new(val))
            .and_then(|boxed| (boxed as Box<dyn Any>).downcast().ok().map(|boxed| *boxed))
    }

    /// Check if container contains value for type
    pub fn contains<T: 'static>(&self) -> bool {
        self.map.get(&TypeId::of::<T>()).is_some()
    }

    /// Get a reference to a value previously inserted on this `Extensions`.
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|boxed| (&**boxed as &(dyn Any)).downcast_ref())
    }

    /// Get a mutable reference to a value previously inserted on this `Extensions`.
    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|boxed| (&mut **boxed as &mut (dyn Any)).downcast_mut())
    }

    /// Remove a value from this `Extensions`.
    ///
    /// If a value of this type exists, it will be returned.
    pub fn remove<T: 'static>(&mut self) -> Option<T> {
        self.map
            .remove(&TypeId::of::<T>())
            .and_then(|boxed| (boxed as Box<dyn Any>).downcast().ok().map(|boxed| *boxed))
    }

    /// Clear the `Extensions` of all inserted values.
    #[inline]
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_extensions() {
        #[derive(Debug, PartialEq)]
        struct MyType(i32);

        let mut map = Extensions::new();

        map.insert(5i32);
        map.insert(MyType(10));

        assert_eq!(map.get(), Some(&5i32));
        assert_eq!(map.get_mut(), Some(&mut 5i32));

        assert_eq!(map.remove::<i32>(), Some(5i32));
        assert!(map.get::<i32>().is_none());

        assert_eq!(map.get::<bool>(), None);
        assert_eq!(map.get(), Some(&MyType(10)));
    }
}
