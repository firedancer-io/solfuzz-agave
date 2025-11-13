use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::elf_generated as fbs_elf;
use solfuzz_agave::proto as pb;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn convert_ctx_proto_to_flatbuf(input: &pb::ElfLoaderCtx) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();

    // input ctx
    let features_off = input.features.as_ref().map(|features| {
        let vec_off = fbb.create_vector(&features.features);
        fbs_ctx::FeatureSet::create(
            &mut fbb,
            &fbs_ctx::FeatureSetArgs {
                features: Some(vec_off),
            },
        )
    });

    let elf_off = input
        .elf
        .as_ref()
        .map(|elf| fbb.create_vector(elf.data.as_slice()));

    let ctx_off = fbs_elf::ELFLoaderCtx::create(
        &mut fbb,
        &fbs_elf::ELFLoaderCtxArgs {
            elf_data: elf_off,
            features: features_off,
            deploy_checks: input.deploy_checks,
        },
    );

    fbb.finish(ctx_off, None);
    fbb.finished_data().to_vec()
}

fn read_file(path: &PathBuf) -> io::Result<Vec<u8>> {
    fs::read(path)
}

fn decode_ctx(bytes: &[u8]) -> Result<pb::ElfLoaderCtx, prost::DecodeError> {
    pb::ElfLoaderCtx::decode(bytes)
}

fn process_file(path: &PathBuf, out_dir: &PathBuf) -> i32 {
    match read_file(path) {
        Ok(bytes) => match decode_ctx(&bytes) {
            Ok(ctx) => {
                let out = convert_ctx_proto_to_flatbuf(&ctx);
                // Write to output directory with same filename
                if let Err(e) = fs::create_dir_all(out_dir) {
                    eprintln!(
                        "{}: failed to create output dir {}: {}",
                        path.display(),
                        out_dir.display(),
                        e
                    );
                    return 1;
                }
                let Some(file_name) = path.file_name() else {
                    eprintln!("{}: invalid file name", path.display());
                    return 1;
                };
                let out_path = out_dir.join(file_name);
                match fs::write(&out_path, &out) {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!(
                            "{}: failed to write {}: {}",
                            path.display(),
                            out_path.display(),
                            e
                        );
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{}: failed to decode protobuf ElfLoaderCtx: {}",
                    path.display(),
                    e
                );
                1
            }
        },
        Err(e) => {
            eprintln!("{}: failed to read: {}", path.display(), e);
            1
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: convert_elf <output_dir> <file1.pb> <file2.pb> ...");
        std::process::exit(1);
    }

    let out_dir = PathBuf::from(&args[0]);
    let mut status = 0;
    for arg in &args[1..] {
        let path = PathBuf::from(arg);
        status |= process_file(&path, &out_dir);
    }
    std::process::exit(status);
}
