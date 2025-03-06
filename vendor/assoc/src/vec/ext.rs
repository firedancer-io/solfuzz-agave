use std::borrow::Borrow;
use std::fmt;
use std::slice::{Iter, IterMut};
use std::vec::IntoIter;

use crate::vec::{Entry, OccupiedEntry, VacantEntry};

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Keys<'a, K: 'a, V: 'a> {
    inner: Iter<'a, (K, V)>,
}

impl<'a, K, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<&'a K> {
        self.inner.next().map(|(k, _)| k)
    }
}

impl<K: fmt::Debug, V> fmt::Debug for Keys<'_, K, V> {
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(format!("{:?}", map.keys()), r#"["a", "b"]"#);
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<K, V> Clone for Keys<'_, K, V> {
    fn clone(&self) -> Self {
        Keys {
            inner: self.inner.clone(),
        }
    }
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoKeys<K, V> {
    inner: IntoIter<(K, V)>,
}

impl<K, V> Iterator for IntoKeys<K, V> {
    type Item = K;

    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
}

impl<K: fmt::Debug, V> fmt::Debug for IntoKeys<K, V> {
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(format!("{:?}", map.into_keys()), r#"["a", "b"]"#);
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.as_slice().iter().map(|(k, _)| k))
            .finish()
    }
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Values<'a, K: 'a, V: 'a> {
    inner: Iter<'a, (K, V)>,
}

impl<'a, K, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        self.inner.next().map(|(_, v)| v)
    }
}

impl<K, V: fmt::Debug> fmt::Debug for Values<'_, K, V> {
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(format!("{:?}", map.values()), "[1, 2]");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<K, V> Clone for Values<'_, K, V> {
    fn clone(&self) -> Self {
        Values {
            inner: self.inner.clone(),
        }
    }
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ValuesMut<'a, K: 'a, V: 'a> {
    inner: IterMut<'a, (K, V)>,
}

impl<'a, K, V> Iterator for ValuesMut<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<&'a mut V> {
        self.inner.next().map(|(_, v)| v)
    }
}

impl<K, V: fmt::Debug> fmt::Debug for ValuesMut<'_, K, V> {
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(format!("{:?}", map.values_mut()), "[1, 2]");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.as_slice().iter().map(|(_, v)| v))
            .finish()
    }
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoValues<K, V> {
    inner: IntoIter<(K, V)>,
}

impl<K, V> Iterator for IntoValues<K, V> {
    type Item = V;

    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
}

impl<K, V: fmt::Debug> fmt::Debug for IntoValues<K, V> {
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(format!("{:?}", map.into_values()), "[1, 2]");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.as_slice().iter().map(|(_, v)| v))
            .finish()
    }
}

/// A trait extension that allows vectors to be treated as associative arrays.
pub trait AssocExt<K, V> {
    /// Get a key's entry for in-place manipulation.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut count = Vec::new();
    /// for x in vec!["a", "b", "c", "b"] {
    ///     *count.entry(x).or_insert(0) += 1;
    /// }
    /// assert_eq!(count.get(&"b"), Some(&2));
    /// ```
    fn entry(&mut self, key: K) -> Entry<K, V>;

    /// Get a reference to the value associated with a key.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(map.get(&"a"), Some(&1));
    /// ```
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    /// Get a mutable reference to the value associated with a key.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// *map.get_mut(&"a").unwrap() += 1;
    /// assert_eq!(map.get(&"a"), Some(&2));
    /// ```
    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    /// Insert a key-value pair into the associative array.
    /// If the map previously had the key, then the old value is returned. Otherwise, `None` is
    /// returned.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("b", 3)];
    /// assert_eq!(AssocExt::insert(&mut map, "a", 1), None);
    /// assert_eq!(AssocExt::insert(&mut map, "a", 2), Some(1));
    /// ```
    fn insert(&mut self, key: K, value: V) -> Option<V>;

    /// Remove a key from the map, returning the value if it was previously in the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1)];
    /// assert_eq!(AssocExt::remove(&mut map, "a"), Some(1));
    /// assert_eq!(AssocExt::remove(&mut map, "a"), None);
    /// ```
    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    /// Get an iterator over the keys of the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// let mut iter = map.keys();
    ///
    /// assert_eq!(iter.next().unwrap(), &"a");
    /// assert_eq!(iter.next().unwrap(), &"b");
    /// assert_eq!(iter.next(), None);
    /// ```
    fn keys(&self) -> Keys<'_, K, V>;

    /// Create a consuming iterator visiting all the keys of the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![(1, "a"), (2, "b")];
    /// let keys: Vec<i32> = map.into_keys().collect();
    /// assert_eq!(keys, [1, 2]);
    /// ```
    fn into_keys(self) -> IntoKeys<K, V>;

    /// Get an iterator over the values of the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// let mut iter = map.values();
    ///
    /// assert_eq!(iter.next().unwrap(), &1);
    /// assert_eq!(iter.next().unwrap(), &2);
    /// assert_eq!(iter.next(), None);
    /// ```
    fn values(&self) -> Values<'_, K, V>;

    /// Get a mutable iterator over the values of the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![(1, "a".to_string()), (2, "b".to_string())];
    ///
    /// for value in map.values_mut() {
    ///     value.push_str("!");
    /// }
    ///
    /// let values: Vec<String> = map.values().cloned().collect();
    /// assert_eq!(values, ["a!".to_string(), "b!".to_string()]);
    /// ```
    fn values_mut(&mut self) -> ValuesMut<'_, K, V>;

    /// Create a consuming iterator visiting all the values of the map.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let map = vec![(1, "a"), (2, "b")];
    /// let values: Vec<&str> = map.into_values().collect();
    /// assert_eq!(values, ["a", "b"]);
    /// ```
    fn into_values(self) -> IntoValues<K, V>;
}

impl<K, V> AssocExt<K, V> for Vec<(K, V)>
where
    K: PartialEq,
{
    fn entry(&mut self, key: K) -> Entry<K, V> {
        let found = self.iter_mut().enumerate().find(|(_, (k, _))| k == &key);
        match found {
            None => Entry::Vacant(VacantEntry::new(self, key)),
            Some((index, _)) => Entry::Occupied(OccupiedEntry::new(self, key, index)),
        }
    }

    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.iter().find(|(k, _)| k.borrow() == key).map(|(_, v)| v)
    }

    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.iter_mut()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.entry(key) {
            Entry::Occupied(mut entry) => Some(entry.insert(value)),
            Entry::Vacant(entry) => {
                entry.insert(value);
                None
            }
        }
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        let found = self
            .iter_mut()
            .enumerate()
            .find(|(_, (k, _))| k.borrow() == key);
        match found {
            None => None,
            Some((index, _)) => {
                let (_, v) = self.swap_remove(index);
                Some(v)
            }
        }
    }

    fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    fn into_keys(self) -> IntoKeys<K, V> {
        IntoKeys {
            inner: self.into_iter(),
        }
    }

    fn values(&self) -> Values<'_, K, V> {
        Values { inner: self.iter() }
    }

    fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    fn into_values(self) -> IntoValues<K, V> {
        IntoValues {
            inner: self.into_iter(),
        }
    }
}

/// This has the same API as [`AssocExt`] but with the additional constraint `K: Eq`.
///
/// ```compile_fail
/// use assoc::AssocStrictExt;
///
/// let map = vec![(1.0, 1), (2.0, 2)];
/// map.entry(1.0);
/// ```
pub trait AssocStrictExt<K, V> {
    /// Get a key's entry for in-place manipulation.
    ///
    /// ```rust
    /// use assoc::AssocStrictExt;
    ///
    /// let mut count = Vec::new();
    /// for x in vec!["a", "b", "c", "b"] {
    ///     *count.entry(x).or_insert(0) += 1;
    /// }
    /// assert_eq!(count.get(&"b"), Some(&2));
    /// ```
    fn entry(&mut self, key: K) -> Entry<K, V>;

    /// Get a reference to the value associated with a key.
    ///
    /// ```rust
    /// use assoc::AssocStrictExt;
    ///
    /// let map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(map.get(&"a"), Some(&1));
    /// ```
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    /// Get a mutable reference to the value associated with a key.
    ///
    /// ```rust
    /// use assoc::AssocStrictExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// *map.get_mut(&"a").unwrap() += 1;
    /// assert_eq!(map.get(&"a"), Some(&2));
    /// ```
    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    /// Insert a key-value pair into the associative array.
    /// If the map previously had the key, then the old value is returned. Otherwise, `None` is
    /// returned.
    ///
    /// ```rust
    /// use assoc::AssocStrictExt;
    ///
    /// let mut map = vec![("b", 3)];
    /// assert_eq!(AssocStrictExt::insert(&mut map, "a", 1), None);
    /// assert_eq!(AssocStrictExt::insert(&mut map, "a", 2), Some(1));
    /// ```
    fn insert(&mut self, key: K, value: V) -> Option<V>;

    /// Remove a key from the map, returning the value if it was previously in the map.
    ///
    /// ```rust
    /// use assoc::AssocStrictExt;
    ///
    /// let mut map = vec![("a", 1)];
    /// assert_eq!(AssocStrictExt::remove(&mut map, "a"), Some(1));
    /// assert_eq!(AssocStrictExt::remove(&mut map, "a"), None);
    /// ```
    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized;

    fn keys(&self) -> Keys<'_, K, V>;
    fn into_keys(self) -> IntoKeys<K, V>;
    fn values(&self) -> Values<'_, K, V>;
    fn values_mut(&mut self) -> ValuesMut<'_, K, V>;
    fn into_values(self) -> IntoValues<K, V>;
}

impl<K, V> AssocStrictExt<K, V> for Vec<(K, V)>
where
    K: Eq,
{
    fn entry(&mut self, key: K) -> Entry<K, V> {
        AssocExt::entry(self, key)
    }

    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        AssocExt::get(self, key)
    }

    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        AssocExt::get_mut(self, key)
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        AssocExt::insert(self, key, value)
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        AssocExt::remove(self, key)
    }

    fn keys(&self) -> Keys<'_, K, V> {
        AssocExt::keys(self)
    }

    fn into_keys(self) -> IntoKeys<K, V> {
        AssocExt::into_keys(self)
    }

    fn values(&self) -> Values<'_, K, V> {
        AssocExt::values(self)
    }

    fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        AssocExt::values_mut(self)
    }

    fn into_values(self) -> IntoValues<K, V> {
        AssocExt::into_values(self)
    }
}
