# SolFuzz-Agave

SolFuzz-Agave provides [SolFuzz](https://github.com/firedancer-io/solfuzz) API bindings for Agave components. These API bindings have native support in Firedancer, but not in Agave. This harness simply wraps pieces of Agave's execution layer to provide the necessary APIs to run fuzz tests on Agave components.

It only supports `x86_64-unknown-linux-gnu` targets.

Supported APIs:

- `sol_compat_elf_loader_v1`
- `sol_compat_get_features_v1`
- `sol_compat_get_metadata_v1`
- `sol_compat_instr_execute_v1`
- `sol_compat_pack_compute_budget_v1`
- `sol_compat_shred_parse_v1`
- `sol_compat_txn_execute_v1`
- `sol_compat_vm_interp_v1`
- `sol_compat_vm_syscall_execute_v1`

## How to Use

Install dependencies:
```sh
# For Ubuntu:
apt install libudev-dev pkg-config
# For RHEL:
sudo dnf install -y systemd-devel

git submodule update --init --recursive
./deps.sh
```
### NOTE FOR LOCAL COPIES

You must use the [firedancer fork](https://github.com/firedancer-io/agave) of Agave with the corresponding 
`patches` branch.

For example, solfuzz-agave branch `agave-v3.0.3` should checkout `agave-v3.0.3-patches` in the fork.

Running with a local copy of Agave (for easily adding print statements):
```sh
./scripts/generate_cargo.py -p <your_local_agave_path> -o Cargo.toml
```

Running with a specific Agave commit:
```sh
./scripts/generate_cargo.py -c <commit_hash> -o Cargo.toml
```

Running with a specific protosol version:
```sh
./scripts/generate_cargo.py -c <commit_hash> -v <version> -o Cargo.toml
# Example: ./scripts/generate_cargo.py -c <commit_hash> -v 1.0.4 -o Cargo.toml
```

Check and test:

```sh
cargo check
cargo test
```

Build:

```sh
make build
make conformance
```

Produces file `target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so`, which is a SolFuzz target that can be used with [Solana-Conformance](https://github.com/firedancer-io/solana-conformance) and [SolFuzz](https://github.com/firedancer-io/solfuzz).

The resulting file is instrumented with sancov.

```
$ ldd target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so
        linux-vdso.so.1 (0x00007ffdaeba8000)
        libgcc_s.so.1 => /lib64/libgcc_s.so.1 (0x00007f328c8e4000)
        libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f328c6c4000)
        libm.so.6 => /lib64/libm.so.6 (0x00007f328c342000)
        libdl.so.2 => /lib64/libdl.so.2 (0x00007f328c13e000)
        libc.so.6 => /lib64/libc.so.6 (0x00007f328bd79000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f328ef71000)

$ nm -D target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so | grep '__sanitizer'
                 U __sanitizer_cov_8bit_counters_init
                 U __sanitizer_cov_pcs_init
                 U __sanitizer_cov_trace_pc_indir
```

**Note:** Protobuf definitions are now managed through the `protosol` Rust crate dependency. The `protosol` crate is automatically included in the generated Cargo.toml with a specific version tag. When protobuf schema changes are needed, maintainers should update the `PROTOSOL_VERSION_TAG` in `scripts/generate_cargo.py` to the appropriate version tag from the [protosol repository](https://github.com/firedancer-io/protosol/).

## Building Targets with Core BPF Programs

SolFuzz-Agave can be used with tools like [Solana-Conformance](https://github.com/firedancer-io/solana-conformance) and [SolFuzz](https://github.com/firedancer-io/solfuzz) to test for conformance between a builtin program and its [Core BPF](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0088-enable-core-bpf-programs.md) version.

For this use case, contributors may wish to build one target which contains the builtin version, and then another target which contains the BPF version. This concept is oriented around the contents of the compiled target's [program JIT cache](https://github.com/anza-xyz/agave/blob/6c6c26eec4317e06e334609ea686b0192a210092/program-runtime/src/loaded_programs.rs#L654).

By default, SolFuzz-Agave populates the program JIT cache with each of the Solana protocol's builtin programs when the entrypoint for an instruction (`sol_compat_instr_execute_v1`) is invoked (see the `load_builtins` function in `lib.rs`). A combination of a feature flag and compile-time environment variables can be used to override a builtin in the program JIT cache.

Available features:
* `core-bpf`: Simply overrides the builtin with the provided BPF program, no other special-casing.
* `core-bpf-conformance`: Overrides the builtin with the provided BPF program and additionally enables certain logic to handle known mismatches between builtins and BPF programs. This feature is primarily intended for the `run-tests` function of Solana-Conformance.

Required variables:
* `CORE_BPF_PROGRAM_ID`: The program ID of the builtin that should be overriden in the cache.
* `CORE_BPF_TARGET`: The path to the program's ELF file (`.so` file) to use in place of the builtin.

**Note:** You may continue to use the same program ID and ELF file path in consecutive compilations, but the program ELF itself has changed. Rustc has no way to know about this change, since the environment variables have not changed. As a result, you can optionally provide `FORCE_RECOMPILE=true` to recompile the underlying macro that does the builtin override, to ensure the compiled target has the latest ELF.

The overriding of a builtin is done via [macro](./macro/), which generates code only when either the `core-bpf` or `core-bpf-conformance` feature is enabled. This code will perform the override, as well as a few other related tasks.

A convenience script is available to assist in building targets with Core BPF programs. It can be found at [`scripts/build_core_bpf.sh`](./scripts/build_core_bpf.sh) and supports a set of specific program IDs currently. Simply add your program ID t this list and the list defined in the macro (`SUPPORTED_BUILTINS`) to add it to the workflow.

## Building Targets with BPF Programs

Similar to Core BPF conformance testing, this harness can also build targets for BPF-BPF conformance testing. However, testing for conformance between two BPF programs, rather than a builtin and its BPF version, requires none of the special-casing mentioned in the above section. A similar mechanism to the above section can be used to build two targets for two versions of a BPF program.

Again, this method keys on the contents of each target's compiled [program JIT cache](https://github.com/anza-xyz/agave/blob/6c6c26eec4317e06e334609ea686b0192a210092/program-runtime/src/loaded_programs.rs#L654).

Available features:
* `bpf-program-conformance`: Allows the developer to provide a program ID and a path to an ELF file via environment variables to manually load the program cache for a given program.

Required variables:
* `BPF_PROGRAM_ID`: The program ID of the program that should be loaded into the cache.
* `BPF_TARGET`: The path to the program's ELF file (`.so` file) to load into the cache.
