use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::elf_generated as fbs_elf;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn convert_fixture_proto_to_flatbuf(input: &pb::ElfLoaderFixture) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();

    // metadata
    let metadata_off = input.metadata.as_ref().map(|m| {
        let ent = fbb.create_string(&m.fn_entrypoint);
        fbs_meta::FixtureMetadata::create(
            &mut fbb,
            &fbs_meta::FixtureMetadataArgs {
                fn_entrypoint: Some(ent),
            },
        )
    });

    // input ctx
    let input_off = input.input.as_ref().map(|ctx| {
        let features_off = ctx.features.as_ref().and_then(|fs| {
            if fs.features.is_empty() {
                None
            } else {
                let vec_off = fbb.create_vector(&fs.features);
                Some(fbs_ctx::FeatureSet::create(
                    &mut fbb,
                    &fbs_ctx::FeatureSetArgs {
                        features: Some(vec_off),
                    },
                ))
            }
        });
        let elf_off = ctx.elf.as_ref().map(|elf| {
            let data_off = fbb.create_vector(&elf.data);
            fbs_elf::ELFBinary::create(
                &mut fbb,
                &fbs_elf::ELFBinaryArgs {
                    data: Some(data_off),
                },
            )
        });
        fbs_elf::ELFLoaderCtx::create(
            &mut fbb,
            &fbs_elf::ELFLoaderCtxArgs {
                elf: elf_off,
                features: features_off,
                deploy_checks: ctx.deploy_checks,
            },
        )
    });

    // output effects
    let output_off = input.output.as_ref().map(|eff| {
        let rodata_off = if eff.rodata.is_empty() {
            None
        } else {
            Some(fbb.create_vector(&eff.rodata))
        };
        let calldests_off = if eff.calldests.is_empty() {
            None
        } else {
            Some(fbb.create_vector(&eff.calldests))
        };
        fbs_elf::ELFLoaderEffects::create(
            &mut fbb,
            &fbs_elf::ELFLoaderEffectsArgs {
                rodata: rodata_off,
                rodata_sz: eff.rodata_sz,
                text_cnt: eff.text_cnt,
                text_off: eff.text_off,
                entry_pc: eff.entry_pc,
                calldests: calldests_off,
                err_code: eff.error as u8,
            },
        )
    });

    let fixture_off = fbs_elf::ELFLoaderFixture::create(
        &mut fbb,
        &fbs_elf::ELFLoaderFixtureArgs {
            metadata: metadata_off,
            input: input_off,
            output: output_off,
        },
    );
    fbb.finish(fixture_off, None);
    fbb.finished_data().to_vec()
}

fn read_file(path: &PathBuf) -> io::Result<Vec<u8>> {
    fs::read(path)
}

fn decode_fixture(bytes: &[u8]) -> Result<pb::ElfLoaderFixture, prost::DecodeError> {
    pb::ElfLoaderFixture::decode(bytes)
}

fn process_file(path: &PathBuf, out_dir: &PathBuf) -> i32 {
    match read_file(path) {
        Ok(bytes) => match decode_fixture(&bytes) {
            Ok(fixture) => {
                let out = convert_fixture_proto_to_flatbuf(&fixture);
                // Write to output directory with same filename
                if let Err(e) = fs::create_dir_all(&out_dir) {
                    eprintln!(
                        "{}: failed to create output dir {}: {}",
                        path.display(),
                        out_dir.display(),
                        e
                    );
                    return 1;
                }
                let file_name = match path.file_name() {
                    Some(name) => name,
                    None => {
                        eprintln!("{}: invalid file name", path.display());
                        return 1;
                    }
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
                    "{}: failed to decode protobuf ElfLoaderFixture: {}",
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
