use clap::Parser;
use prost::Message;
use solfuzz_agave::elf_loader::sol_compat_elf_loader_v1;
use solfuzz_agave::proto::ElfLoaderEffects;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    inputs: Vec<PathBuf>,
}

// Simple executable that loads ELF files/fuzz corpus and prints effects
// Can be used for coverage analysis
fn main() {
    let cli = Cli::parse();
    for input in cli.inputs {
        let mut blob = std::fs::read(input).unwrap();
        let mut out = vec![0u8; 1 << 27];
        unsafe {
            let out_psz: *mut u64 = &mut (out.len() as u64) as *mut u64;
            if sol_compat_elf_loader_v1(
                out.as_mut_ptr(),
                out_psz,
                blob.as_mut_ptr(),
                blob.len() as u64,
            ) == 1
            {
                let out_sz = *out_psz as usize;
                let effects = ElfLoaderEffects::decode(&out[..out_sz]).unwrap();
                eprintln!(
                    "Effects generated. Text section count: {}",
                    effects.text_cnt
                );
            } else {
                eprintln!("No elf loader effects returned.");
            }
        }
    }
}
