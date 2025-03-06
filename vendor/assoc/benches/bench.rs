#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use assoc::AssocExt;
    use std::collections::{BTreeMap, HashMap};
    use test::{black_box, Bencher};

    const ITERATIONS: u128 = 40;

    #[bench]
    fn bench_vec(b: &mut Bencher) {
        let mut map = Vec::new();

        b.iter(|| {
            for i in 0..ITERATIONS {
                black_box(map.entry(i).or_insert(2 * i));
            }
        });
    }

    #[bench]
    fn bench_hashmap(b: &mut Bencher) {
        let mut map = HashMap::new();

        b.iter(|| {
            for i in 0..ITERATIONS {
                black_box(map.entry(i).or_insert(2 * i));
            }
        });
    }

    #[bench]
    fn bench_btreemap(b: &mut Bencher) {
        let mut map = BTreeMap::new();

        b.iter(|| {
            for i in 0..ITERATIONS {
                black_box(map.entry(i).or_insert(2 * i));
            }
        });
    }
}
