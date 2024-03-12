solfuzz-agave provides solfuzz API bindings for Agave components.
Only supports x86_64-unknown-linux-gnu targets.

Check and test:

```sh
cargo check
cargo test
```

Build:

```sh
make toolchain
make build
```

Produces file `target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so`

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
