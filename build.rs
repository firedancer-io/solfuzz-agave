use std::io::Result;

fn main() -> Result<()> {
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

    let proto_base_path = std::path::PathBuf::from("protosol/proto");

    let protos = &[
        proto_base_path.join("invoke.proto"),
        proto_base_path.join("vm.proto"),
        proto_base_path.join("txn.proto"),
        proto_base_path.join("elf.proto"),
        proto_base_path.join("shred.proto"),
        proto_base_path.join("pack.proto"),
    ];

    protos
        .iter()
        .for_each(|proto| println!("cargo:rerun-if-changed={}", proto.display()));

    prost_build::compile_protos(protos, &[proto_base_path])?;

    Ok(())
}
