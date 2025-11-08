use std::{env, fs, path::PathBuf};
extern crate flatc_rust;

fn monitor_and_get_files(
    env_var: &str,
    extension: &str,
) -> Result<(Vec<PathBuf>, PathBuf), Box<dyn std::error::Error>> {
    // Get absolute dir from producer
    let dir = PathBuf::from(env::var(env_var).expect(&format!(
        "protosol did not expose {}, did protosol build.rs run first?",
        env_var
    )));

    println!("cargo:rerun-if-env-changed={}", env_var);
    println!("cargo:rerun-if-changed={}", dir.display());

    // Collect absolute paths
    let mut files = vec![];
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push(path);
        }
    }

    // Ensure deterministic order for rebuilds
    files.sort();

    Ok((files, dir))
}

fn compile_protos() -> Result<(), Box<dyn std::error::Error>> {
    let (proto_files, proto_dir) = monitor_and_get_files("DEP_PROTOSOL_PROTO_DIR", "proto")?;

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

fn compile_flatbuffers() -> Result<(), Box<dyn std::error::Error>> {
    let (flatbuffer_files, flatbuffer_dir) =
        monitor_and_get_files("DEP_PROTOSOL_FLATBUFFERS_DIR", "fbs")?;

    // Compile flatbuffers into Rust
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Use custom flatc from ./opt/bin/flatc relative to this build.rs
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let flatc_path = manifest_dir.join("opt").join("bin").join("flatc");

    let flatc = flatc_rust::Flatc::from_path(&flatc_path);
    flatc.check()?;
    flatc.run(flatc_rust::Args {
        lang: "rust",
        inputs: flatbuffer_files
            .iter()
            .map(|p| p.as_path())
            .collect::<Vec<_>>()
            .as_slice(),
        out_dir: out_dir.as_path(),
        includes: &[flatbuffer_dir.as_path()],
        extra: &["--gen-object-api", "--gen-compare"],
        ..Default::default()
    })?;
    Ok(())
}

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

    compile_protos()?;
    compile_flatbuffers()?;

    Ok(())
}
