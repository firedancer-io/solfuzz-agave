use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::instr_generated as fbs_instr;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn convert_pubkey(pk: &[u8]) -> fbs_ctx::Pubkey {
    let mut arr = [0u8; 32];
    let copy_len = core::cmp::min(arr.len(), pk.len());
    arr[..copy_len].copy_from_slice(&pk[..copy_len]);
    fbs_ctx::Pubkey::new(&arr)
}

fn convert_feature_set<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    fs: &pb::FeatureSet,
) -> Option<flatbuffers::WIPOffset<fbs_ctx::FeatureSet<'a>>> {
    if fs.features.is_empty() {
        None
    } else {
        let features_off = fbb.create_vector(&fs.features);
        Some(fbs_ctx::FeatureSet::create(
            fbb,
            &fbs_ctx::FeatureSetArgs {
                features: Some(features_off),
            },
        ))
    }
}

fn convert_account<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    a: &pb::AcctState,
) -> flatbuffers::WIPOffset<fbs_ctx::Account<'a>> {
    let data_off = fbb.create_vector(&a.data);
    let addr = convert_pubkey(&a.address);
    let owner = convert_pubkey(&a.owner);
    fbs_ctx::Account::create(
        fbb,
        &fbs_ctx::AccountArgs {
            address: Some(&addr),
            lamports: a.lamports,
            data: Some(data_off),
            executable: a.executable,
            owner: Some(&owner),
        },
    )
}

fn convert_instr_account<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ia: &pb::InstrAcct,
) -> flatbuffers::WIPOffset<fbs_instr::InstrAccount<'a>> {
    fbs_instr::InstrAccount::create(
        fbb,
        &fbs_instr::InstrAccountArgs {
            index: ia.index as u8,
            is_signer: ia.is_signer,
            is_writable: ia.is_writable,
        },
    )
}

fn convert_instr_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ctx: &pb::InstrContext,
) -> flatbuffers::WIPOffset<fbs_instr::InstrContext<'a>> {
    // Convert feature set
    let features_off = ctx
        .epoch_context
        .as_ref()
        .and_then(|epoch_ctx| epoch_ctx.features.as_ref())
        .and_then(|fs| convert_feature_set(fbb, fs));

    // Convert account states
    let account_states: Vec<_> = ctx
        .accounts
        .iter()
        .map(|acct| convert_account(fbb, acct))
        .collect();
    let account_states_off = fbb.create_vector(&account_states);

    // Convert instruction accounts
    let instr_accounts: Vec<_> = ctx
        .instr_accounts
        .iter()
        .map(|ia| convert_instr_account(fbb, ia))
        .collect();
    let instr_accounts_off = fbb.create_vector(&instr_accounts);

    // Convert instruction data
    let instr_data_off = fbb.create_vector(&ctx.data);

    // Convert program_id
    let program_id = convert_pubkey(&ctx.program_id);

    fbs_instr::InstrContext::create(
        fbb,
        &fbs_instr::InstrContextArgs {
            program_id: Some(&program_id),
            account_states: Some(account_states_off),
            instr_accounts: Some(instr_accounts_off),
            cu_avail: ctx.cu_avail,
            instr_data: Some(instr_data_off),
            features: features_off,
        },
    )
}

fn convert_instr_effects<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    effects: &pb::InstrEffects,
) -> flatbuffers::WIPOffset<fbs_instr::InstrEffects<'a>> {
    // Convert modified accounts
    let modified_accounts: Vec<_> = effects
        .modified_accounts
        .iter()
        .map(|acct| convert_account(fbb, acct))
        .collect();
    let modified_accounts_off = if modified_accounts.is_empty() {
        None
    } else {
        Some(fbb.create_vector(&modified_accounts))
    };

    // Convert return data (always create a vector, even if empty)
    let return_data_off = fbb.create_vector(&effects.return_data);

    fbs_instr::InstrEffects::create(
        fbb,
        &fbs_instr::InstrEffectsArgs {
            err_code: effects.result as u8,
            custom_err_code: effects.custom_err,
            modified_accounts: modified_accounts_off,
            cu_remaining: effects.cu_avail,
            return_data: Some(return_data_off),
        },
    )
}

fn convert_instr_fixture<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    fixture: &pb::InstrFixture,
) -> flatbuffers::WIPOffset<fbs_instr::InstrFixture<'a>> {
    // Convert metadata
    let metadata_off = fixture.metadata.as_ref().map(|m| {
        let ent = fbb.create_string(&m.fn_entrypoint);
        fbs_meta::FixtureMetadata::create(
            fbb,
            &fbs_meta::FixtureMetadataArgs {
                fn_entrypoint: Some(ent),
            },
        )
    });

    let input_off = fixture
        .input
        .as_ref()
        .map(|ctx| convert_instr_context(fbb, ctx));

    let output_off = fixture
        .output
        .as_ref()
        .map(|effects| convert_instr_effects(fbb, effects));

    fbs_instr::InstrFixture::create(
        fbb,
        &fbs_instr::InstrFixtureArgs {
            metadata: metadata_off,
            input: input_off,
            output: output_off,
        },
    )
}

fn convert_file(input_path: &PathBuf, output_path: &PathBuf) -> io::Result<()> {
    // Read protobuf fixture
    let pb_data = fs::read(input_path)?;
    let pb_fixture = pb::InstrFixture::decode(&pb_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Convert to flatbuffer
    let mut fbb = FlatBufferBuilder::with_capacity(1 << 20); // 1MB initial capacity
    let fb_fixture = convert_instr_fixture(&mut fbb, &pb_fixture);
    fbb.finish_minimal(fb_fixture);

    // Write flatbuffer fixture
    fs::write(output_path, fbb.finished_data())?;

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <output_dir> <input_files...>", args[0]);
        eprintln!("  <output_dir>: Directory to write flatbuffer .fix files");
        eprintln!("  <input_files...>: One or more protobuf .fix files to convert");
        std::process::exit(1);
    }

    let output_dir = PathBuf::from(&args[1]);
    let input_files: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();

    // Create output directory if it doesn't exist
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).expect("Failed to create output directory");
    }

    let mut total = 0;
    let mut success = 0;
    let mut failed = 0;

    for input_path in input_files {
        if !input_path.is_file() {
            eprintln!("✗ Skipping non-file: {:?}", input_path);
            continue;
        }

        total += 1;
        let file_name = input_path.file_name().unwrap();
        let output_path = output_dir.join(file_name);
        match convert_file(&input_path, &output_path) {
            Ok(_) => {
                println!("✓ Converted: {:?}", input_path);
                success += 1;
            }
            Err(e) => {
                eprintln!("✗ Failed to convert {:?}: {}", input_path, e);
                failed += 1;
            }
        }
    }

    println!("\nConversion complete:");
    println!("  Total: {}", total);
    println!("  Success: {}", success);
    println!("  Failed: {}", failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
