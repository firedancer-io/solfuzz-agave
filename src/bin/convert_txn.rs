use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use solfuzz_agave::txn_generated as fbs_txn;
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

fn convert_hash(h: &[u8]) -> fbs_ctx::Hash {
    let mut arr = [0u8; 32];
    let copy_len = core::cmp::min(arr.len(), h.len());
    arr[..copy_len].copy_from_slice(&h[..copy_len]);
    fbs_ctx::Hash::new(&arr)
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

fn convert_tx_message<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    m: &pb::TransactionMessage,
    message_hash: &[u8],
    signatures: &[Vec<u8>],
) -> flatbuffers::WIPOffset<fbs_txn::TransactionMessage<'a>> {
    let header = m.header.as_ref().unwrap_or(&pb::MessageHeader {
        num_required_signatures: 0,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 0,
    });
    let header_off = fbs_txn::MessageHeader::create(
        fbb,
        &fbs_txn::MessageHeaderArgs {
            num_required_signatures: header.num_required_signatures as u8,
            num_readonly_signed_accounts: header.num_readonly_signed_accounts as u8,
            num_readonly_unsigned_accounts: header.num_readonly_unsigned_accounts as u8,
        },
    );

    // account keys as Pubkey vector
    let acct_keys: Vec<fbs_ctx::Pubkey> =
        m.account_keys.iter().map(|k| convert_pubkey(k)).collect();
    let acct_keys_off = fbb.create_vector(&acct_keys);

    // recent blockhash and message hash
    let recent_blockhash = convert_hash(&m.recent_blockhash);
    let msg_hash = convert_hash(message_hash);

    // instructions
    let mut instrs: Vec<flatbuffers::WIPOffset<fbs_txn::CompiledInstruction<'a>>> =
        Vec::with_capacity(m.instructions.len());
    for ix in &m.instructions {
        let acct_idx_u8: Vec<u8> = ix.accounts.iter().map(|&a| a as u8).collect();
        let accts_off = fbb.create_vector(&acct_idx_u8);
        let data_off = fbb.create_vector(&ix.data);
        let ix_off = fbs_txn::CompiledInstruction::create(
            fbb,
            &fbs_txn::CompiledInstructionArgs {
                program_id_index: ix.program_id_index as u8,
                accounts: Some(accts_off),
                data: Some(data_off),
            },
        );
        instrs.push(ix_off);
    }
    let instrs_off = fbb.create_vector(&instrs);

    // address lookup tables
    let mut alts: Vec<flatbuffers::WIPOffset<fbs_txn::AddressLookupTable<'a>>> =
        Vec::with_capacity(m.address_table_lookups.len());
    for alt in &m.address_table_lookups {
        let key = convert_pubkey(&alt.account_key);
        let writable_u8: Vec<u8> = alt.writable_indexes.iter().map(|&x| x as u8).collect();
        let readonly_u8: Vec<u8> = alt.readonly_indexes.iter().map(|&x| x as u8).collect();
        let writable_off = fbb.create_vector(&writable_u8);
        let readonly_off = fbb.create_vector(&readonly_u8);
        let alt_off = fbs_txn::AddressLookupTable::create(
            fbb,
            &fbs_txn::AddressLookupTableArgs {
                account_key: Some(&key),
                writable_indexes: Some(writable_off),
                readonly_indexes: Some(readonly_off),
            },
        );
        alts.push(alt_off);
    }
    let alts_off = fbb.create_vector(&alts);

    // signatures
    let sigs: Vec<fbs_ctx::Signature> = signatures
        .iter()
        .map(|s| {
            let mut arr = [0u8; 64];
            let n = core::cmp::min(arr.len(), s.len());
            arr[..n].copy_from_slice(&s[..n]);
            fbs_ctx::Signature::new(&arr)
        })
        .collect();
    let sigs_off = fbb.create_vector(&sigs);

    fbs_txn::TransactionMessage::create(
        fbb,
        &fbs_txn::TransactionMessageArgs {
            is_legacy: m.is_legacy,
            header: Some(header_off),
            account_keys: Some(acct_keys_off),
            recent_blockhash: Some(&recent_blockhash),
            instructions: Some(instrs_off),
            address_lookup_tables: Some(alts_off),
            message_hash: Some(&msg_hash),
            signatures: Some(sigs_off),
        },
    )
}

fn convert_txn_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ctx: &pb::TxnContext,
) -> flatbuffers::WIPOffset<fbs_txn::TxnContext<'a>> {
    // transaction message
    let default_tx;
    let tx = match ctx.tx.as_ref() {
        Some(t) => t,
        None => {
            default_tx = pb::SanitizedTransaction {
                message: None,
                message_hash: vec![],
                signatures: vec![],
            };
            &default_tx
        }
    };

    let default_msg;
    let msg = match tx.message.as_ref() {
        Some(m) => m,
        None => {
            default_msg = pb::TransactionMessage {
                is_legacy: true,
                header: None,
                account_keys: vec![],
                recent_blockhash: vec![],
                instructions: vec![],
                address_table_lookups: vec![],
            };
            &default_msg
        }
    };

    let tx_msg_off = convert_tx_message(fbb, msg, &tx.message_hash, &tx.signatures);

    // account states
    let mut accounts: Vec<flatbuffers::WIPOffset<fbs_ctx::Account<'a>>> =
        Vec::with_capacity(ctx.account_shared_data.len());
    for a in &ctx.account_shared_data {
        accounts.push(convert_account(fbb, a));
    }
    let accounts_off = fbb.create_vector(&accounts);

    // blockhash queue
    let mut bhq_hashes: Vec<fbs_ctx::Hash> = Vec::with_capacity(ctx.blockhash_queue.len());
    for h in &ctx.blockhash_queue {
        bhq_hashes.push(convert_hash(h));
    }
    let bhq_off = fbb.create_vector(&bhq_hashes);

    // features
    let features_off = ctx
        .epoch_ctx
        .as_ref()
        .and_then(|epoch_ctx| epoch_ctx.features.as_ref())
        .and_then(|fs| convert_feature_set(fbb, fs));

    fbs_txn::TxnContext::create(
        fbb,
        &fbs_txn::TxnContextArgs {
            txn_message: Some(tx_msg_off),
            account_states: Some(accounts_off),
            blockhash_queue: Some(bhq_off),
            features: features_off,
        },
    )
}

fn convert_txn_effects<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    result: &pb::TxnResult,
) -> flatbuffers::WIPOffset<fbs_txn::TxnEffects<'a>> {
    // modified accounts
    let modified_accounts_off = if let Some(resulting_state) = result.resulting_state.as_ref() {
        let mut accounts: Vec<flatbuffers::WIPOffset<fbs_ctx::Account<'a>>> =
            Vec::with_capacity(resulting_state.acct_states.len());
        for a in &resulting_state.acct_states {
            accounts.push(convert_account(fbb, a));
        }
        Some(fbb.create_vector(&accounts))
    } else {
        None
    };

    // return data - only create if transaction was executed (not FeesOnly or error)
    let return_data_off = if result.executed {
        Some(fbb.create_vector(&result.return_data))
    } else {
        None
    };

    // fee details
    let fee_details_off = result.fee_details.as_ref().map(|fd| {
        fbs_txn::FeeDetails::create(
            fbb,
            &fbs_txn::FeeDetailsArgs {
                transaction_fee: fd.transaction_fee,
                prioritization_fee: fd.prioritization_fee,
            },
        )
    });

    fbs_txn::TxnEffects::create(
        fbb,
        &fbs_txn::TxnEffectsArgs {
            txn_err_code: result.status as u8,
            instr_err_code: result.instruction_error as u8,
            instr_err_idx: result.instruction_error_index as u8,
            custom_err_code: result.custom_error,
            executed_units: result.executed_units,
            loaded_accounts_data_size: result.loaded_accounts_data_size as u32,
            modified_accounts: modified_accounts_off,
            return_data: return_data_off,
            fee_details: fee_details_off,
        },
    )
}

fn convert_fixture_proto_to_flatbuf<'a>(
    input: &pb::TxnFixture,
    fbb: &mut FlatBufferBuilder<'a>,
) -> Vec<u8> {
    // metadata
    let metadata_off = if let Some(m) = input.metadata.as_ref() {
        let ent = fbb.create_string(&m.fn_entrypoint);
        Some(fbs_meta::FixtureMetadata::create(
            fbb,
            &fbs_meta::FixtureMetadataArgs {
                fn_entrypoint: Some(ent),
            },
        ))
    } else {
        None
    };

    // input ctx
    let input_off = if let Some(ctx) = input.input.as_ref() {
        Some(convert_txn_context(fbb, ctx))
    } else {
        None
    };

    // output effects
    let output_off = if let Some(result) = input.output.as_ref() {
        Some(convert_txn_effects(fbb, result))
    } else {
        None
    };

    let fixture_off = fbs_txn::TxnFixture::create(
        fbb,
        &fbs_txn::TxnFixtureArgs {
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

fn decode_fixture(bytes: &[u8]) -> Result<pb::TxnFixture, prost::DecodeError> {
    pb::TxnFixture::decode(bytes)
}

fn process_file(path: &PathBuf, out_dir: &PathBuf) -> i32 {
    match read_file(path) {
        Ok(bytes) => match decode_fixture(&bytes) {
            Ok(fixture) => {
                let mut builder = FlatBufferBuilder::with_capacity(1 << 17);
                let out = convert_fixture_proto_to_flatbuf(&fixture, &mut builder);
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
                    "{}: failed to decode protobuf TxnFixture: {}",
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
        eprintln!("usage: convert_txn <output_dir> <file1.fix> <file2.fix> ...");
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
