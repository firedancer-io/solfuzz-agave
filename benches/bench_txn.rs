// Benchmark transaction execution using test vectors in dump/test-vectors/txn/fixtures/programs/
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use prost::Message;
use solfuzz_agave::proto::TxnContext;
use solfuzz_agave::proto::TxnFixture;
use std::fs;

fn bench_txn_exec(c: &mut Criterion) {
    unsafe {
        solfuzz_agave::sol_compat_init(0);
    }

    // Read in fixtures
    println!("{:?}", std::env::current_dir());
    let current_dir = std::env::current_dir().unwrap();
    let fixtures_dir = current_dir.join("dump/test-vectors/txn/fixtures/programs/");
    println!("Looking for fixtures in: {:?}", fixtures_dir);

    if !fixtures_dir.exists() {
        panic!(
            "Fixtures directory does not exist: {}. Please ensure the path is correct and accessible.",
            fixtures_dir.display()
        );
    }

    let entries = match fs::read_dir(&fixtures_dir) {
        Ok(e) => e,
        Err(e) => {
            panic!(
                "Failed to read fixtures dir: {}: {}, can you please make sure it's findable at {}?",
                fixtures_dir.display(),
                e,
                "dump/test-vectors/txn/fixtures/programs/"
            );
        }
    };

    // Load all contexts into memory
    let mut contexts_vec: Vec<TxnContext> = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().map(|e| e == "fix").unwrap_or(false) {
            let blob = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to read {}: {}", path.display(), e);
                    continue;
                }
            };
            let fixture = match TxnFixture::decode(&blob[..]) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to decode fixture {}: {}", path.display(), e);
                    continue;
                }
            };
            let context = match fixture.input {
                Some(i) => i,
                None => {
                    eprintln!("Fixture {} has no input context", path.display());
                    continue;
                }
            };
            contexts_vec.push(context);
        }
    }

    println!("Loaded {} fixtures", contexts_vec.len());

    if contexts_vec.is_empty() {
        panic!("No valid fixtures found!");
    }

    let mut group = c.benchmark_group("txn-fixture-exec");
    group.bench_function("all-fixtures-batch", |b| {
        b.iter(|| {
            let sample = &contexts_vec[..std::cmp::min(100, contexts_vec.len())];

            for context in sample {
                black_box(solfuzz_agave::txn_fuzzer::execute_transaction(
                    context,
                ));
            }
        });
    });

    // Optional: Also benchmark individual fixture execution to get per-transaction metrics
    if contexts_vec.len() < 20 {
        // Only do individual benchmarks for small sets
        for (idx, context) in contexts_vec.iter().enumerate() {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("fixture-{}", idx)),
                context,
                |b, ctx| {
                    b.iter(|| {
                        black_box(solfuzz_agave::txn_fuzzer::execute_transaction(ctx));
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_txn_exec);
criterion_main!(benches);
