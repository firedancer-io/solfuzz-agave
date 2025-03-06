/// A view into a single entry in an associative array. The entry may be vacant or occupied.
///
/// Returned by the [`AssocExt::entry`][crate::AssocExt::entry] method.
#[derive(Debug)]
pub enum Entry<'a, K, V>
where
    K: 'a,
    V: 'a,
{
    /// A vacant entry.
    Vacant(VacantEntry<'a, K, V>),

    /// An occupied entry.
    Occupied(OccupiedEntry<'a, K, V>),
}

/// A view into a vacant entry in an associative array. It is part of the [`Entry`] enum.
#[derive(Debug)]
pub struct VacantEntry<'a, K: 'a, V: 'a> {
    vec: &'a mut Vec<(K, V)>,
    key: K,
}

impl<'a, K: 'a, V: 'a> VacantEntry<'a, K, V> {
    pub(crate) fn new(vec: &'a mut Vec<(K, V)>, key: K) -> VacantEntry<'a, K, V> {
        VacantEntry { vec, key }
    }

    /// Get a reference to the key that would be used when inserting a value through a
    /// `VacantEntry`.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Take ownership of the key.
    pub fn into_key(self) -> K {
        self.key
    }

    /// Set the value of the entry, and return a mutable reference to it.
    pub fn insert(self, v: V) -> &'a mut V {
        self.vec.push((self.key, v));
        let (_, v) = self.vec.last_mut().unwrap();
        v
    }
}

/// A view into an occupied entry in an associative array. It is part of the [`Entry`] enum.
#[derive(Debug)]
pub struct OccupiedEntry<'a, K, V> {
    vec: &'a mut Vec<(K, V)>,
    key: K,
    index: usize,
}

impl<'a, K: 'a, V: 'a> OccupiedEntry<'a, K, V> {
    pub(crate) fn new(vec: &'a mut Vec<(K, V)>, key: K, index: usize) -> OccupiedEntry<'a, K, V> {
        OccupiedEntry { vec, key, index }
    }

    /// Get a reference to the key in the entry.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Take ownership of the key-value pair from the associative array.
    pub fn remove_entry(self) -> (K, V) {
        self.vec.swap_remove(self.index)
    }

    /// Get a reference to the value in the entry.
    pub fn get(&self) -> &V {
        let (_, v) = &self.vec[self.index];
        v
    }

    /// Get a mutable reference to the value in the entry.
    pub fn get_mut(&mut self) -> &mut V {
        let (_, v) = &mut self.vec[self.index];
        v
    }

    /// Convert the entry into a mutable reference to the value in the entry.
    /// This mutable reference has a lifetime bound by the lifetime of the associative array.
    pub fn into_mut(self) -> &'a mut V {
        let (_, v) = &mut self.vec[self.index];
        v
    }

    /// Set the value of the entry and return the entry's old value.
    pub fn insert(&mut self, mut v: V) -> V {
        std::mem::swap(&mut v, &mut self.vec[self.index].1);
        v
    }

    /// Take the value out of the entry.
    pub fn remove(self) -> V {
        let (_, v) = self.remove_entry();
        v
    }
}

impl<'a, K, V> Entry<'a, K, V> {
    /// Ensures a value is in the entry by inserting the default if it is empty, and returns a
    /// mutable reference to the value in the entry.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// map.entry("c").or_insert(3);
    /// assert_eq!(map.get(&"c"), Some(&3));
    /// assert_eq!(map.entry("c").or_insert(4), &3);
    /// ```
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Vacant(entry) => entry.insert(default),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Ensures a value is in the entry by inserting the result of the default function if empty,
    /// and returns a mutable reference to the value in the entry.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = Vec::new();
    /// map.entry("c").or_insert_with(|| 3);
    /// assert_eq!(map.get(&"c"), Some(&3));
    /// assert_eq!(map.entry("c").or_insert_with(|| 4), &3);
    /// ```
    pub fn or_insert_with<F>(self, default: F) -> &'a mut V
    where
        F: FnOnce() -> V,
    {
        match self {
            Entry::Vacant(_) => self.or_insert(default()),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Ensures a value is in the entry by inserting, if empty, the result of the default function.
    /// This method allows for generating key-derived values for insertion by providing the default
    /// function a reference to the key that was moved during the `.entry(key)` method call.
    /// The reference to the moved key is provided so that cloning or copying the key is
    /// unnecessary, unlike with [`Entry::or_insert_with`].
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// map.entry("c").or_insert_with_key(|key| key.len());
    /// assert_eq!(map.get(&"c"), Some(&1));
    /// ```
    pub fn or_insert_with_key<F>(self, default: F) -> &'a mut V
    where
        F: FnOnce(&K) -> V,
    {
        match self {
            Entry::Vacant(entry) => {
                let v = default(entry.key());
                entry.insert(v)
            }
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Returns a reference to this entry's key.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// assert_eq!(map.entry("a").key(), &"a");
    /// ```
    pub fn key(&self) -> &K {
        match self {
            Entry::Vacant(entry) => entry.key(),
            Entry::Occupied(entry) => entry.key(),
        }
    }

    /// Provides in-place mutable access to an occupied entry before any potential inserts into the
    /// associative array.
    ///
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// map.entry("c").and_modify(|e| *e += 1).or_insert(3);
    /// assert_eq!(map.get(&"c"), Some(&3));
    ///
    /// map.entry("c").and_modify(|e| *e += 1).or_insert(9);
    /// assert_eq!(map.get(&"c"), Some(&4));
    /// ```
    pub fn and_modify<F>(self, f: F) -> Entry<'a, K, V>
    where
        F: FnOnce(&mut V),
    {
        match self {
            Entry::Vacant(entry) => Entry::Vacant(entry),
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());
                Entry::Occupied(entry)
            }
        }
    }
}

impl<'a, K, V> Entry<'a, K, V>
where
    K: 'a,
    V: 'a + Default,
{
    /// ```rust
    /// use assoc::AssocExt;
    ///
    /// let mut map = vec![("a", 1), ("b", 2)];
    /// map.entry("c").or_default();
    /// assert_eq!(map.get(&"c"), Some(&0));
    /// ```
    pub fn or_default(self) -> &'a mut V {
        self.or_insert_with(Default::default)
    }
}
