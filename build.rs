use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Get absolute proto dir from producer
    let proto_dir = PathBuf::from(
        env::var("DEP_PROTOSOL_PROTO_DIR")
            .expect("protosol did not expose PROTO_DIR, did protosol build.rs run first?"),
    );

    println!("cargo:rerun-if-env-changed=DEP_PROTOSOL_PROTO_DIR");
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    // Collect absolute .proto paths
    let mut proto_files = vec![];
    for entry in fs::read_dir(&proto_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("proto") {
            println!("cargo:rerun-if-changed={}", path.display());
            proto_files.push(path);
        }
    }

    // Ensure deterministic order for rebuilds
    proto_files.sort();

    // Compile protos into Rust
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);

    config.compile_protos(
        &proto_files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        &[proto_dir.to_str().unwrap()],
    )?;

    Ok(())
}
