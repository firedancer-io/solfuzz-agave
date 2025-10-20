use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::block_generated as fbs_block;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use solfuzz_agave::txn_generated as fbs_txn;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

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

fn convert_lthash_from_bytes(bytes: &[u8]) -> fbs_ctx::LtHash {
    // LtHash is 1024 u16s -> 2048 bytes. Incoming protobuf stores as bytes.
    // Truncate or pad to 2048.
    let mut arr_u16 = [0u16; 1024];
    let to_copy = core::cmp::min(bytes.len(), 2048);
    let mut tmp = [0u8; 2048];
    tmp[..to_copy].copy_from_slice(&bytes[..to_copy]);
    // convert little-endian pairs to u16s
    for i in 0..1024 {
        let lo = tmp[2 * i] as u16;
        let hi = tmp[2 * i + 1] as u16;
        arr_u16[i] = lo | (hi << 8);
    }
    fbs_ctx::LtHash::new(&arr_u16)
}

fn convert_vote_account<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    v: &pb::VoteAccount,
) -> flatbuffers::WIPOffset<fbs_ctx::VoteAccount<'a>> {
    let default_acct;
    let acct = match v.vote_account.as_ref() {
        Some(a) => a,
        None => {
            default_acct = pb::AcctState {
                address: vec![],
                lamports: 0,
                data: vec![],
                executable: false,
                owner: vec![],
            };
            &default_acct
        }
    };

    let data_off = fbb.create_vector(&acct.data);
    let addr = convert_pubkey(&acct.address);
    let owner = convert_pubkey(&acct.owner);
    let acct_off = fbs_ctx::Account::create(
        fbb,
        &fbs_ctx::AccountArgs {
            address: Some(&addr),
            lamports: acct.lamports,
            data: Some(data_off),
            executable: acct.executable,
            owner: Some(&owner),
        },
    );

    fbs_ctx::VoteAccount::create(
        fbb,
        &fbs_ctx::VoteAccountArgs {
            vote_account: Some(acct_off),
            stake: v.stake,
        },
    )
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

fn convert_block_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ctx: &pb::BlockContext,
) -> flatbuffers::WIPOffset<fbs_block::BlockContext<'a>> {
    // transactions
    let mut tx_msgs: Vec<flatbuffers::WIPOffset<fbs_txn::TransactionMessage<'a>>> =
        Vec::with_capacity(ctx.txns.len());
    for stx in &ctx.txns {
        let default_msg;
        let msg = match stx.message.as_ref() {
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
        let tx_off = convert_tx_message(fbb, msg, &stx.message_hash, &stx.signatures);
        tx_msgs.push(tx_off);
    }
    let tx_msgs_off = fbb.create_vector(&tx_msgs);

    // account states
    let mut accounts: Vec<flatbuffers::WIPOffset<fbs_ctx::Account<'a>>> =
        Vec::with_capacity(ctx.acct_states.len());
    for a in &ctx.acct_states {
        accounts.push(convert_account(fbb, a));
    }
    let accounts_off = fbb.create_vector(&accounts);

    // blockhash queue
    let mut bhq_hashes: Vec<fbs_ctx::Hash> = Vec::with_capacity(ctx.blockhash_queue.len());
    for h in &ctx.blockhash_queue {
        bhq_hashes.push(convert_hash(h));
    }
    let bhq_off = fbb.create_vector(&bhq_hashes);

    // bank fields come from slot_ctx + epoch_ctx
    let default_slot;
    let slot = match ctx.slot_ctx.as_ref() {
        Some(s) => s,
        None => {
            default_slot = pb::SlotContext {
                slot: 0,
                block_height: 0,
                poh: vec![],
                parent_bank_hash: vec![],
                parent_lthash: vec![],
                prev_slot: 0,
                prev_lps: 0,
                prev_epoch_capitalization: 0,
                fee_rate_governor: None,
                parent_signature_count: 0,
            };
            &default_slot
        }
    };
    let default_epoch;
    let epoch = match ctx.epoch_ctx.as_ref() {
        Some(e) => e,
        None => {
            default_epoch = pb::EpochContext {
                features: None,
                hashes_per_tick: 0,
                ticks_per_slot: 0,
                slots_per_year: 0.0,
                inflation: None,
                genesis_creation_time: 0,
                vote_accounts_t_1: vec![],
                vote_accounts_t_2: vec![],
            };
            &default_epoch
        }
    };

    let fee_gov = slot
        .fee_rate_governor
        .as_ref()
        .unwrap_or(&pb::FeeRateGovernor {
            target_lamports_per_signature: 0,
            target_signatures_per_slot: 0,
            min_lamports_per_signature: 0,
            max_lamports_per_signature: 0,
            burn_percent: 0,
        });
    let fee_gov_off = fbs_block::FeeRateGovernor::create(
        fbb,
        &fbs_block::FeeRateGovernorArgs {
            target_lamports_per_signature: fee_gov.target_lamports_per_signature,
            target_signatures_per_slot: fee_gov.target_signatures_per_slot,
            min_lamports_per_signature: fee_gov.min_lamports_per_signature,
            max_lamports_per_signature: fee_gov.max_lamports_per_signature,
            burn_percent: fee_gov.burn_percent as u8,
        },
    );

    let inflation = match epoch.inflation {
        Some(v) => v,
        None => pb::Inflation {
            initial: 0.0,
            terminal: 0.0,
            taper: 0.0,
            foundation: 0.0,
            foundation_term: 0.0,
        },
    };
    let inflation_off = fbs_block::Inflation::create(
        fbb,
        &fbs_block::InflationArgs {
            initial: inflation.initial,
            terminal: inflation.terminal,
            taper: inflation.taper,
            foundation: inflation.foundation,
            foundation_term: inflation.foundation_term,
        },
    );

    let poh = convert_hash(&slot.poh);
    let parent_bank_hash = convert_hash(&slot.parent_bank_hash);
    let parent_lthash = convert_lthash_from_bytes(&slot.parent_lthash);

    // vote account lists
    let mut votes_t1: Vec<flatbuffers::WIPOffset<fbs_ctx::VoteAccount<'a>>> =
        Vec::with_capacity(epoch.vote_accounts_t_1.len());
    for v in &epoch.vote_accounts_t_1 {
        votes_t1.push(convert_vote_account(fbb, v));
    }
    let votes_t1_off = fbb.create_vector(&votes_t1);
    let mut votes_t2: Vec<flatbuffers::WIPOffset<fbs_ctx::VoteAccount<'a>>> =
        Vec::with_capacity(epoch.vote_accounts_t_2.len());
    for v in &epoch.vote_accounts_t_2 {
        votes_t2.push(convert_vote_account(fbb, v));
    }
    let votes_t2_off = fbb.create_vector(&votes_t2);

    let bank_fields_args = fbs_block::BankFieldsArgs {
        block_height: slot.block_height,
        poh: Some(&poh),
        parent_bank_hash: Some(&parent_bank_hash),
        parent_lthash: Some(&parent_lthash),
        current_slot: slot.slot,
        parent_slot: slot.prev_slot,
        prev_lps: slot.prev_lps,
        fee_rate_governor: Some(fee_gov_off),
        parent_signature_count: slot.parent_signature_count,
        hashes_per_tick: epoch.hashes_per_tick,
        ticks_per_slot: epoch.ticks_per_slot,
        slots_per_year: epoch.slots_per_year,
        inflation: Some(inflation_off),
        genesis_creation_time: epoch.genesis_creation_time,
        prev_epoch_capitalization: slot.prev_epoch_capitalization,
        vote_accounts_t_1: Some(votes_t1_off),
        vote_accounts_t_2: Some(votes_t2_off),
    };
    let bank_fields_off = fbs_block::BankFields::create(fbb, &bank_fields_args);

    let mut features_off = None;
    if let Some(epoch_ctx) = ctx.epoch_ctx.as_ref() {
        if let Some(fs) = epoch_ctx.features.as_ref() {
            features_off = convert_feature_set(fbb, fs);
        }
    }

    fbs_block::BlockContext::create(
        fbb,
        &fbs_block::BlockContextArgs {
            transactions: Some(tx_msgs_off),
            account_states: Some(accounts_off),
            blockhash_queue: Some(bhq_off),
            bank_fields: Some(bank_fields_off),
            features: features_off,
        },
    )
}

fn convert_block_effects<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    eff: &pb::BlockEffects,
) -> flatbuffers::WIPOffset<fbs_block::BlockEffects<'a>> {
    let bank_hash = convert_hash(&eff.bank_hash);

    let cost_tracker_off = if let Some(c) = eff.cost_tracker.as_ref() {
        Some(fbs_block::CostTracker::create(
            fbb,
            &fbs_block::CostTrackerArgs {
                block_cost: c.block_cost,
                vote_cost: c.vote_cost,
            },
        ))
    } else {
        None
    };

    let leader_schedule_off = if let Some(ls) = eff.leader_schedule.as_ref() {
        let mut hash16 = [0u8; 16];
        let n = core::cmp::min(hash16.len(), ls.leader_schedule_hash.len());
        hash16[..n].copy_from_slice(&ls.leader_schedule_hash[..n]);
        let lsh = fbs_block::LeaderScheduleHash::new(&hash16);
        Some(fbs_block::LeaderScheduleEffects::create(
            fbb,
            &fbs_block::LeaderScheduleEffectsArgs {
                leaders_epoch: ls.leaders_epoch,
                leaders_slot0: ls.leaders_slot0,
                leaders_slot_cnt: ls.leaders_slot_cnt,
                leader_pub_cnt: ls.leader_pub_cnt,
                leaders_sched_cnt: ls.leaders_sched_cnt,
                leader_schedule_hash: Some(&lsh),
            },
        ))
    } else {
        None
    };

    fbs_block::BlockEffects::create(
        fbb,
        &fbs_block::BlockEffectsArgs {
            has_err: eff.has_error,
            slot_capitalization: eff.slot_capitalization,
            bank_hash: Some(&bank_hash),
            cost_tracker: cost_tracker_off,
            leader_schedule: leader_schedule_off,
        },
    )
}

fn convert_fixture_proto_to_flatbuf<'a>(
    input: &pb::BlockFixture,
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
        Some(convert_block_context(fbb, ctx))
    } else {
        None
    };

    // output effects
    let output_off = if let Some(eff) = input.output.as_ref() {
        Some(convert_block_effects(fbb, eff))
    } else {
        None
    };

    let fixture_off = fbs_block::BlockFixture::create(
        fbb,
        &fbs_block::BlockFixtureArgs {
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

fn decode_fixture(bytes: &[u8]) -> Result<pb::BlockFixture, prost::DecodeError> {
    pb::BlockFixture::decode(bytes)
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
                    "{}: failed to decode protobuf BlockFixture: {}",
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
        eprintln!("usage: convert_block <output_dir> <file1.pb> <file2.pb> ...");
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
