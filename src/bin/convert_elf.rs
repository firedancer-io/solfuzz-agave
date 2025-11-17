use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::elf_generated as fbs_elf;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use solfuzz_agave::utils::fd_hash::{fd_hash_u64_without_seed, fd_hash_without_seed};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn convert_fixture_proto_to_flatbuf(input: &pb::ElfLoaderFixture) -> Vec<u8> {
    let mut fbb: FlatBufferBuilder<'_> = FlatBufferBuilder::new();

    // metadata
    let fn_entrypoint = input
        .metadata
        .as_ref()
        .map(|m| m.fn_entrypoint.as_str())
        .unwrap_or("");
    let fn_entrypoint_off = fbb.create_string(fn_entrypoint);
    let metadata_off = fbs_meta::FixtureMetadata::create(
        &mut fbb,
        &fbs_meta::FixtureMetadataArgs {
            fn_entrypoint: Some(fn_entrypoint_off),
        },
    );

    // input ctx
    let ctx = input.input.as_ref();
    let feature_values: &[u64] = ctx
        .and_then(|c| c.features.as_ref())
        .map(|features| features.features.as_slice())
        .unwrap_or(&[]);
    let features_vec = fbb.create_vector(feature_values);
    let features_off = Some(fbs_ctx::FeatureSet::create(
        &mut fbb,
        &fbs_ctx::FeatureSetArgs {
            features: Some(features_vec),
        },
    ));

    let elf_bytes: &[u8] = ctx
        .and_then(|c| c.elf.as_ref())
        .map(|elf| elf.data.as_slice())
        .unwrap_or(&[]);
    let elf_off = Some(fbb.create_vector(elf_bytes));

    let deploy_checks = ctx.map(|c| c.deploy_checks).unwrap_or(false);
    let ctx_off = fbs_elf::ELFLoaderCtx::create(
        &mut fbb,
        &fbs_elf::ELFLoaderCtxArgs {
            elf_data: elf_off,
            features: features_off,
            deploy_checks,
        },
    );

    // output effects
    let output = input.output.as_ref();
    let error = output.map(|o| o.error).unwrap_or(0) as u8;
    let text_cnt = output.map(|o| o.text_cnt).unwrap_or(0);
    let text_off = output.map(|o| o.text_off).unwrap_or(0);
    let entry_pc = output.map(|o| o.entry_pc).unwrap_or(0);

    // Compute rodata hash
    let rodata_hash = output.and_then(|o| {
        if !o.rodata.is_empty() {
            let hash_u64 = fd_hash_without_seed(&o.rodata);
            Some(fbs_ctx::XXHash::new(&hash_u64.to_le_bytes()))
        } else {
            None
        }
    });

    // Compute calldests hash
    let calldests_hash = output.and_then(|o| {
        if !o.calldests.is_empty() {
            let hash_u64 = unsafe { fd_hash_u64_without_seed(o.calldests.as_slice()) };
            Some(fbs_ctx::XXHash::new(&hash_u64.to_le_bytes()))
        } else {
            None
        }
    });

    let effects_off = fbs_elf::ELFLoaderEffects::create(
        &mut fbb,
        &fbs_elf::ELFLoaderEffectsArgs {
            err_code: error,
            rodata_hash: rodata_hash.as_ref(),
            text_cnt,
            text_off,
            entry_pc,
            calldests_hash: calldests_hash.as_ref(),
        },
    );

    // fixture
    let fixture_off = fbs_elf::ELFLoaderFixture::create(
        &mut fbb,
        &fbs_elf::ELFLoaderFixtureArgs {
            metadata: Some(metadata_off),
            input: Some(ctx_off),
            output: Some(effects_off),
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
