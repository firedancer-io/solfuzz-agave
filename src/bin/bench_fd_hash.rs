use std::time::Instant;

use clap::Parser;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng as StdRng;
use sha2::{Digest, Sha256};
use solfuzz_agave::fd_hash;

/// Benchmark fd_hash vs sha256 on random byte arrays
#[derive(Parser, Debug, Clone)]
#[command(name = "bench_fd_hash", version, about = "Benchmark fd_hash vs sha256")]
struct Args {
    /// Number of random inputs to hash
    #[arg(long, default_value_t = 1000)]
    iters: usize,

    /// Size of each random input in kilobytes
    #[arg(long, default_value_t = 100)]
    size_kb: usize,

    /// RNG seed for reproducibility
    #[arg(long, default_value_t = 42u64)]
    seed: u64,
}

fn main() {
    let args = Args::parse();

    let bytes_per_input: usize = args
        .size_kb
        .checked_mul(1024)
        .expect("size_kb too large");

    println!(
        "Preparing {} random inputs of {} KB ({} bytes each)\n",
        args.iters, args.size_kb, bytes_per_input
    );

    // Pre-generate inputs so generation cost does not affect hashing timings
    let mut rng = StdRng::seed_from_u64(args.seed);
    let mut inputs = Vec::with_capacity(args.iters);
    for _ in 0..args.iters {
        let mut buf = vec![0u8; bytes_per_input];
        rng.fill_bytes(&mut buf);
        inputs.push(buf);
    }

    // fd_hash benchmark
    let mut fd_accumulator: u64 = 0;
    let start_fd = Instant::now();
    for input in &inputs {
        // fixed seed for apples-to-apples comparison
        fd_accumulator ^= fd_hash(0, input);
    }
    let dur_fd = start_fd.elapsed();

    // sha256 benchmark
    let mut sha_accumulator: u64 = 0;
    let start_sha = Instant::now();
    for input in &inputs {
        let digest = Sha256::digest(input);
        // fold first 8 bytes into a u64 so work cannot be optimized away
        let folded = u64::from_le_bytes(digest[0..8].try_into().expect("slice length")).wrapping_add(1);
        sha_accumulator ^= folded;
    }
    let dur_sha = start_sha.elapsed();

    // Prevent the compiler from optimizing away the loops
    println!("fd_hash accumulator: {}", fd_accumulator);
    println!("sha256 accumulator: {}\n", sha_accumulator);

    let total_bytes: u128 = (args.iters as u128)
        .checked_mul(bytes_per_input as u128)
        .expect("total bytes overflow");

    // Report
    report("fd_hash", args.iters, total_bytes, dur_fd);
    report("sha256", args.iters, total_bytes, dur_sha);
}

fn report(name: &str, iters: usize, total_bytes: u128, duration: std::time::Duration) {
    let secs = duration.as_secs_f64();
    let mb = (total_bytes as f64) / 1_048_576.0; // 1024*1024
    let gb = mb / 1024.0;
    let mbps = mb / secs;
    let gbps = gb / secs;
    let ns_per_input = (duration.as_nanos() as f64) / (iters as f64);

    println!(
        "{}: {:.3} s, {:.2} MB processed ({:.3} GB), {:.2} MB/s ({:.3} GB/s)",
        name, secs, mb, gb, mbps, gbps
    );
    println!(
        "{} latency: {:.1} ns per input\n",
        name, ns_per_input
    );
}
