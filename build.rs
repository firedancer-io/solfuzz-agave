use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=CORE_BPF_PROGRAM_ID");
    println!("cargo:rerun-if-env-changed=CORE_BPF_TARGET");

    let proto_base_path = std::path::PathBuf::from("proto");

    let protos = &[
        proto_base_path.join("invoke.proto"),
        proto_base_path.join("vm.proto"),
        proto_base_path.join("elf.proto")
    ];

    protos
        .iter()
        .for_each(|proto| println!("cargo:rerun-if-changed={}", proto.display()));

    prost_build::compile_protos(protos, &[proto_base_path])?;

    Ok(())
}
