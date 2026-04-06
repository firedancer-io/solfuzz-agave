fn main() {
    // Tells rustc to recompile the `load_core_bpf_program!` macro if either
    // of the required environment variables has changed.
    println!("cargo:rerun-if-env-changed=CORE_BPF_PROGRAM_ID");
    println!("cargo:rerun-if-env-changed=CORE_BPF_TARGET");
    // Sometimes, the environment variables may be exactly the same, but the
    // program binary itself may have changed. One can provide a
    // `FORCE_RECOMPILE=true` to force the macro to re-compile.
    if std::env::var("FORCE_RECOMPILE").as_deref() == Ok("true") {
        println!("cargo:rerun-if-changed=force_rebuild");
    }
}
