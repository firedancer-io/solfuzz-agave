# Lazy LRU cache

Typically, an LRU cache is implemented using a combination of a hash map and a
doubly linked list. The doubly linked list keeps track of the order in which
the items were accessed.
When an entry is accessed or inserted into the cache, its respective reference
is moved to (or inserted at) the front of the linked list. Doing so, the least
recently used item is always at the back of the linked list and is evicted as
soon as the cache size exceeds its designated capacity.

This crate instead implements an alternative variant of LRU cache with _lazy_
eviction:
* Each entry maintains an associated ordinal value representing when the entry
  was last accessed.
* The cache is allowed to grow up to 2 times the specified capacity with no
  evictions, at which point, the excess entries are evicted based on LRU policy
  in linear time resulting in an _amortized_ `O(1)` performance.

In many use cases which can allow the cache to store 2 times the capacity and
can tolerate the amortized nature of performance, this results in a better
average performance as shown by the benchmarks in this crate:

```
test bench_get_eager ... bench:      21,434 ns/iter (+/- 3,565)
test bench_get_lazy  ... bench:      16,514 ns/iter (+/- 385)
test bench_put_eager ... bench:      52,277 ns/iter (+/- 25,473)
test bench_put_lazy  ... bench:      33,117 ns/iter (+/- 5,057)
```

Additionally, with the eager implementation, lookups require a mutable
reference `&mut self` to allow updating internal linked list.
In a multi-threaded setting, this requires an exclusive write-lock on the cache
even on the read path, which can exacerbate lock contentions.
With lazy eviction, the ordinal values can be updated using atomic operations,
allowing shared lock for lookups.
