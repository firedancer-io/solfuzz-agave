extern crate proc_macro;

use {
    proc_macro::TokenStream,
    quote::{quote, ToTokens},
    solana_sdk::pubkey::Pubkey,
    std::{fs::File, io::Read, path::Path, str::FromStr},
};

struct PubkeyBytes([u8; 32]);
impl ToTokens for PubkeyBytes {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let bytes = self.0.iter().map(|b| quote! { #b });
        tokens.extend(quote! { [#(#bytes),*] });
    }
}

struct ElfBytes(Vec<u8>);
impl ToTokens for ElfBytes {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let bytes = self.0.iter().map(|b| quote! { #b });
        tokens.extend(quote! { vec![#(#bytes),*] });
    }
}

const SUPPORTED_BUILTINS: [Pubkey; 2] = [
    solana_sdk::address_lookup_table::program::id(),
    solana_sdk::config::program::id(),
];

fn read_file(path: &Path) -> Vec<u8> {
    let mut file = File::open(path)
        .unwrap_or_else(|err| panic!("Failed to open \"{}\": {}", path.display(), err));

    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)
        .unwrap_or_else(|err| panic!("Failed to read \"{}\": {}", path.display(), err));
    file_data
}

#[proc_macro]
pub fn load_core_bpf_program(_: TokenStream) -> TokenStream {
    if let Ok(program_id_str) = std::env::var("CORE_BPF_PROGRAM_ID") {
        let program_id = Pubkey::from_str(&program_id_str).expect("Invalid address");
        if !SUPPORTED_BUILTINS.contains(&program_id) {
            panic!("Unsupported program id: {}", program_id);
        }
        let program_id_bytes = PubkeyBytes(program_id.to_bytes());

        let elf_path = std::env::var("CORE_BPF_TARGET").expect("CORE_BPF_TARGET not set");
        let elf_data = read_file(Path::new(&elf_path));
        let elf_bytes = ElfBytes(elf_data);

        return quote! {
            let program_id = Pubkey::new_from_array(#program_id_bytes);
            let elf = #elf_bytes;
            cache.replenish(
                program_id,
                Arc::new(
                    solana_program_runtime::loaded_programs::LoadedProgram::new(
                        &solana_sdk::bpf_loader_upgradeable::id(),
                        cache.environments.program_runtime_v1.clone(),
                        0,
                        0,
                        &elf,
                        elf.len(),
                        &mut solana_program_runtime::loaded_programs::LoadProgramMetrics::default(),
                    )
                    .unwrap(),
                ),
            );
        }
        .into();
    }

    quote!().into()
}
