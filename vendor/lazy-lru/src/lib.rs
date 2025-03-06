#![no_std]
use {
    alloc::vec::Vec,
    core::{
        borrow::Borrow,
        cmp::Reverse,
        hash::Hash,
        iter::FusedIterator,
        sync::atomic::{AtomicU64, Ordering},
    },
    hashbrown::HashMap,
};

extern crate alloc;

/// A least-recently-used (LRU) Cache with lazy eviction.
/// Each entry maintains an associated ordinal value representing when the
/// entry was last accessed. The cache is allowed to grow up to 2 times
/// specified capacity with no evictions, at which point, the excess entries
/// are evicted based on LRU policy resulting in an _amortized_ `O(1)`
/// performance.
#[derive(Debug)]
pub struct LruCache<K, V> {
    cache: HashMap<K, (/*ordinal:*/ AtomicU64, V)>,
    counter: AtomicU64,
    capacity: usize,
}

/// An iterator over the entries of an `LruCache`.
/// This `struct` is created by the [`iter`] method on [`LruCache`].
///
/// [`iter`]: LruCache::iter
#[derive(Clone)]
pub struct Iter<'a, K: 'a, V: 'a>(hashbrown::hash_map::Iter<'a, K, (AtomicU64, V)>);

/// A mutable iterator over the entries of an `LruCache`.
/// This `struct` is created by the [`iter_mut`] method on [`LruCache`].
///
/// [`iter_mut`]: LruCache::iter_mut
pub struct IterMut<'a, K: 'a, V: 'a>(hashbrown::hash_map::IterMut<'a, K, (AtomicU64, V)>);

/// An owning iterator over the entries of an `LruCache`.
/// This `struct` is created by the [`into_iter`] method on [`LruCache`]
/// (provided by the [`IntoIterator`] trait). See its documentation for more.
///
/// [`into_iter`]: IntoIterator::into_iter
pub struct IntoIter<K, V>(hashbrown::hash_map::IntoIter<K, (AtomicU64, V)>);

impl<K, V> LruCache<K, V> {
    pub fn new(capacity: usize) -> LruCache<K, V> {
        Self {
            cache: HashMap::with_capacity(capacity.saturating_mul(2)),
            counter: AtomicU64::default(),
            capacity,
        }
    }

    /// An iterator visiting all key-value pairs in arbitrary order.
    /// The iterator element type is `(&'a K, &'a V)`.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter(self.cache.iter())
    }

    /// An iterator visiting all key-value pairs in arbitrary order, with
    /// mutable references to the values.
    /// The iterator element type is `(&'a K, &'a mut V)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut(self.cache.iter_mut())
    }
}

impl<K: Eq + Hash + PartialEq, V> LruCache<K, V> {
    /// Inserts a key-value pair into the cache.
    /// If the cache not have this key present, None is returned.
    /// If the cache did have this key present, the value is updated, and the
    /// old value is returned. The key is not updated, though; this matters for
    /// types that can be `==` without being identical.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let ordinal = self.counter.fetch_add(1, Ordering::Relaxed);
        let old = self
            .cache
            .insert(key, (AtomicU64::new(ordinal), value))
            .map(|(_, value)| value);
        self.maybe_evict();
        old
    }

    // If the cache hash grown to at least twice the self.capacity, evicts
    // extra entries from the cache by LRU policy.
    fn maybe_evict(&mut self) {
        if self.cache.len() < self.capacity.saturating_mul(2) {
            return;
        }
        let mut entries: Vec<(K, (/*ordinal:*/ u64, V))> = self
            .cache
            .drain()
            .map(|(key, (ordinal, value))| (key, (ordinal.into_inner(), value)))
            .collect();
        entries
            .select_nth_unstable_by_key(self.capacity.saturating_sub(1), |&(_, (ordinal, _))| {
                Reverse(ordinal)
            });
        self.cache.extend(
            entries
                .into_iter()
                .take(self.capacity)
                .map(|(key, (ordinal, value))| (key, (AtomicU64::new(ordinal), value))),
        );
    }

    /// Returns true if the cache contains a value for the specified key.
    /// Unlike `self.get(key).is_some()`, this method does _not_ update the
    /// LRU ordinal value associated with the entry.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.contains_key(key)
    }

    /// Returns a reference to the value corresponding to the key.
    /// Updates the LRU ordinal value associated with the entry.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let (ordinal, value) = self.cache.get(key)?;
        // fetch_max instead of store here because of possible concurrent
        // lookups of the same key.
        ordinal.fetch_max(
            self.counter.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        Some(value)
    }

    /// Returns a mutable reference to the value corresponding to the key.
    /// Updates the LRU ordinal value associated with the entry.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let (ordinal, value) = self.cache.get_mut(key)?;
        // store is sufficient here because &mut self prevents concurrent
        // update.
        ordinal.store(
            self.counter.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        Some(value)
    }

    /// Returns the key-value pair corresponding to the supplied key.
    /// Updates the LRU ordinal value associated with the entry.
    ///
    /// The supplied key may be any borrowed form of the cache's key type, but
    /// `Hash` and `Eq` on the borrowed form must match those for the key type.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let (key, (ordinal, value)) = self.cache.get_key_value(key)?;
        // fetch_max instead of store here because of possible concurrent
        // lookups of the same key.
        ordinal.fetch_max(
            self.counter.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        Some((key, value))
    }

    /// Returns a reference to the value corresponding to the key.
    /// Unlike [`get`], `peek` does _not_ updates the LRU ordinal value
    /// associated with the entry.
    ///
    /// [`get`]: LruCache::get
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.get(key).map(|(_, value)| value)
    }

    /// Returns a mutable reference to the value corresponding to the key.
    /// Unlike [`get_mut`], `peek_mut` does _not_ updates the LRU ordinal value
    /// associated with the entry.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    ///
    /// [`get_mut`]: LruCache::get_mut
    pub fn peek_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.get_mut(key).map(|(_, value)| value)
    }

    /// Returns the key-value pair corresponding to the supplied key.
    /// Unlike [`get_key_value`], `peek_key_value` does _not_ updates the
    /// ordinal value associated with the entry.
    ///
    /// The supplied key may be any borrowed form of the cache's key type, but
    /// `Hash` and `Eq` on the borrowed form must match those for the key type.
    ///
    /// [`get_key_value`]: LruCache::get_key_value
    pub fn peek_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache
            .get_key_value(key)
            .map(|(key, (_, value))| (key, value))
    }

    /// Removes a key from the cache, returning the value at the key if the key
    /// was previously in the cache.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.remove(key).map(|(_, value)| value)
    }

    /// Removes a key from the cache, returning the stored key and value if the
    /// key was previously in the cache.
    ///
    /// The key may be any borrowed form of the cache's key type, but `Hash`
    /// and `Eq` on the borrowed form must match those for the key type.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache
            .remove_entry(key)
            .map(|(key, (_, value))| (key, value))
    }

    /// Synonym for [`remove`].
    ///
    /// [`remove`]: LruCache::remove
    pub fn pop<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove(key)
    }

    /// Synonym for [`remove_entry`].
    ///
    /// [`remove_entry`]: LruCache::remove_entry
    pub fn pop_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_entry(key)
    }

    /// Returns the number of elements in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clears the cache, removing all key-value pairs.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Retains only the elements specified by the predicate.
    /// In other words, remove all pairs `(k, v)` for which `f(&k, &mut v)`
    /// returns `false`. The elements are visited in unsorted (and unspecified)
    /// order.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.cache.retain(|key, (_, value)| f(key, value));
    }
}

impl<K: Clone + Eq + Hash + PartialEq, V: Clone> LruCache<K, V> {
    /// Clones the `LruCache`.
    ///
    /// Note: `&mut self` is necessary to prevent interior mutation from
    /// concurrent access while the cache is cloned.
    pub fn clone(&mut self) -> Self {
        let cache = self.cache.iter().map(|(key, (ordinal, value))| {
            let ordinal = AtomicU64::new(ordinal.load(Ordering::Relaxed));
            (key.clone(), (ordinal, value.clone()))
        });
        Self {
            cache: cache.collect(),
            counter: AtomicU64::new(self.counter.load(Ordering::Relaxed)),
            ..*self
        }
    }
}

impl<'a, K, V> IntoIterator for &'a LruCache<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K, V> IntoIterator for &'a mut LruCache<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    #[inline]
    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

impl<K, V> IntoIterator for LruCache<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    #[inline]
    fn into_iter(self) -> IntoIter<K, V> {
        IntoIter(self.cache.into_iter())
    }
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    #[inline]
    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        self.0.next().map(|(key, (_, value))| (key, value))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        Self: Sized,
        F: FnMut(B, Self::Item) -> B,
    {
        self.0.fold(init, |acc, entry| {
            let (key, (_, value)) = entry;
            f(acc, (key, value))
        })
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<K, V> FusedIterator for Iter<'_, K, V> {}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    #[inline]
    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        self.0.next().map(|(key, (_, value))| (key, value))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        Self: Sized,
        F: FnMut(B, Self::Item) -> B,
    {
        self.0.fold(init, |acc, entry| {
            let (key, (_, value)) = entry;
            f(acc, (key, value))
        })
    }
}

impl<K, V> ExactSizeIterator for IterMut<'_, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<K, V> FusedIterator for IterMut<'_, K, V> {}

impl<K, V> Iterator for IntoIter<K, V> {
    type Item = (K, V);

    #[inline]
    fn next(&mut self) -> Option<(K, V)> {
        self.0.next().map(|(key, (_, value))| (key, value))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        Self: Sized,
        F: FnMut(B, Self::Item) -> B,
    {
        self.0.fold(init, |acc, entry| {
            let (key, (_, value)) = entry;
            f(acc, (key, value))
        })
    }
}

impl<K, V> ExactSizeIterator for IntoIter<K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<K, V> FusedIterator for IntoIter<K, V> {}

#[cfg(test)]
mod tests {
    use {
        super::*,
        core::{fmt::Debug, num::NonZeroUsize},
        rand::Rng,
        test_case::test_case,
    };

    fn check_entry<K, V, Q: ?Sized>(cache: &LruCache<K, V>, key: &Q, ordinal: u64, value: V)
    where
        K: Hash + Eq + Borrow<Q>,
        Q: Hash + Eq,
        V: Debug + PartialEq<V>,
    {
        let (entry_ordinal, entry_value) = cache.cache.get(key).unwrap();
        assert_eq!(entry_value, &value);
        assert_eq!(entry_ordinal.load(Ordering::Relaxed), ordinal);
    }

    #[test]
    fn test_capacity_zero() {
        let mut cache = LruCache::new(0);

        cache.put("apple", 8);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get("apple"), None);
    }

    #[test]
    fn test_basics() {
        let mut cache = LruCache::new(2);

        cache.put("apple", 8);
        assert_eq!(cache.len(), 1);
        check_entry(&cache, "apple", 0, 8);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 1);

        assert_eq!(cache.peek("apple"), Some(&8));
        check_entry(&cache, "apple", 0, 8);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 1);

        assert_eq!(cache.peek_mut("apple"), Some(&mut 8));
        check_entry(&cache, "apple", 0, 8);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 1);

        assert_eq!(cache.get("apple"), Some(&8));
        check_entry(&cache, "apple", 1, 8);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 2);

        assert_eq!(cache.get_mut("apple"), Some(&mut 8));
        check_entry(&cache, "apple", 2, 8);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 3);

        cache.put("banana", 4);
        assert_eq!(cache.len(), 2);
        check_entry(&cache, "banana", 3, 4);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 4);

        cache.put("pear", 2);
        assert_eq!(cache.len(), 3);
        check_entry(&cache, "pear", 4, 2);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 5);

        cache.put("banana", 6);
        assert_eq!(cache.len(), 3);
        check_entry(&cache, "banana", 5, 6);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 6);

        cache.put("orange", 3); // triggers eviction
        assert_eq!(cache.len(), 2);
        check_entry(&cache, "banana", 5, 6);
        check_entry(&cache, "orange", 6, 3);
        assert_eq!(cache.counter.load(Ordering::Relaxed), 7);

        assert!(cache.contains_key("banana"));
        assert!(cache.contains_key("orange"));
        assert!(!cache.contains_key("apple"));
        assert!(!cache.contains_key("pear"));

        assert_eq!(cache.remove("banana"), Some(6));
        assert_eq!(cache.remove("banana"), None);

        assert_eq!(cache.remove_entry("orange"), Some(("orange", 3)));
        assert_eq!(cache.remove_entry("orange"), None);

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test_case(10, 10)]
    #[test_case(10, 100)]
    #[test_case(10, 1_000)]
    #[test_case(10, 10_000)]
    #[test_case(100, 10)]
    #[test_case(100, 100)]
    #[test_case(100, 1_000)]
    #[test_case(100, 10_000)]
    fn test_lru_cache_cross_check_subset(capacity: usize, num_keys: usize) {
        let mut rng = rand::thread_rng();
        let mut cache = LruCache::<usize, u8>::new(capacity);
        let mut other = lru::LruCache::<usize, u8>::new(NonZeroUsize::new(capacity).unwrap());
        for _ in 0..10_000_000 {
            let key: usize = rng.gen_range(0..num_keys);
            if rng.gen_ratio(1, 2) {
                let val = other.get(&key);
                assert!(val.is_none() || cache.get(&key) == val);
            } else {
                let val = rng.gen();
                let old = other.put(key, val);
                assert!(cache.put(key, val) == old || old.is_none());
            }
        }
    }

    #[test_case(10, 10)]
    #[test_case(10, 100)]
    #[test_case(10, 1_000)]
    #[test_case(10, 10_000)]
    #[test_case(100, 10)]
    #[test_case(100, 100)]
    #[test_case(100, 1_000)]
    #[test_case(100, 10_000)]
    fn test_lru_cache_cross_check_superset(capacity: usize, num_keys: usize) {
        let mut rng = rand::thread_rng();
        let mut cache = LruCache::<usize, u8>::new(capacity);
        let mut other = lru::LruCache::<usize, u8>::new(NonZeroUsize::new(2 * capacity).unwrap());
        for _ in 0..10_000_000 {
            let key: usize = rng.gen_range(0..num_keys);
            if rng.gen_ratio(1, 2) {
                let val = cache.get(&key);
                assert!(val.is_none() || other.get(&key) == val);
            } else {
                let val = rng.gen();
                let old = cache.put(key, val);
                assert!(other.put(key, val) == old || old.is_none());
            }
        }
    }
}
