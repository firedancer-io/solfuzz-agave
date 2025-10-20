use flatbuffers::FlatBufferBuilder;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::elf_generated::*;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn extract_elf_loader_ctx_to_flatbuf(ctx: ELFLoaderCtx) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();

    // Extract features if present
    let features_off = {
        let features_vec = ctx.features().features().map(|v| {
            // Convert Vector<u64> to a Vec<u64> by iterating
            let features: Vec<u64> = (0..v.len()).map(|i| v.get(i)).collect();
            fbb.create_vector(&features)
        });
        fbs_ctx::FeatureSet::create(
            &mut fbb,
            &fbs_ctx::FeatureSetArgs {
                features: features_vec,
            },
        )
    };

    // Extract ELF data
    let elf_bytes = ctx.elf_data().bytes();
    let elf_off = Some(fbb.create_vector(elf_bytes));

    let ctx_off = ELFLoaderCtx::create(
        &mut fbb,
        &ELFLoaderCtxArgs {
            elf_data: elf_off,
            features: Some(features_off),
            deploy_checks: ctx.deploy_checks(),
        },
    );

    fbb.finish(ctx_off, None);
    fbb.finished_data().to_vec()
}

fn read_file(path: &PathBuf) -> io::Result<Vec<u8>> {
    fs::read(path)
}

fn process_file(path: &PathBuf, out_dir: &PathBuf) -> i32 {
    match read_file(path) {
        Ok(bytes) => {
            let fixture = match flatbuffers::root::<ELFLoaderFixture>(&bytes) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{}: failed to parse flatbuffer: {:?}", path.display(), e);
                    return 1;
                }
            };

            let ctx = fixture.input();
            let out = extract_elf_loader_ctx_to_flatbuf(ctx);

            // Create output directory if it doesn't exist
            if let Err(e) = fs::create_dir_all(out_dir) {
                eprintln!(
                    "{}: failed to create output dir {}: {}",
                    path.display(),
                    out_dir.display(),
                    e
                );
                return 1;
            }

            // Get the base filename and change extension to .elfctx
            let Some(file_stem) = path.file_stem() else {
                eprintln!("{}: invalid file name", path.display());
                return 1;
            };

            let mut out_filename = file_stem.to_os_string();
            out_filename.push(".elfctx");
            let out_path = out_dir.join(out_filename);

            match fs::write(&out_path, &out) {
                Ok(_) => {
                    println!("{} -> {}", path.display(), out_path.display());
                    0
                }
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
            eprintln!("{}: failed to read: {}", path.display(), e);
            1
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: extract_elf_ctx <output_dir> <fixture1> <fixture2> ...");
        eprintln!("Extracts ElfLoaderCtx from ElfLoaderFixture flatbuffer files");
        eprintln!("and saves them as flatbuffer files with .elfctx extension.");
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
