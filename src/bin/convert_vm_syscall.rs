use flatbuffers::FlatBufferBuilder;
use prost::Message;
use solfuzz_agave::context_generated as fbs_ctx;
use solfuzz_agave::instr_generated as fbs_instr;
use solfuzz_agave::metadata_generated as fbs_meta;
use solfuzz_agave::proto as pb;
use solfuzz_agave::vm_generated as fbs_vm;
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
            is_writable: ia.is_writable,
            is_signer: ia.is_signer,
        },
    )
}

fn convert_instr_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ctx: &pb::InstrContext,
) -> flatbuffers::WIPOffset<fbs_instr::InstrContext<'a>> {
    let program_id = convert_pubkey(&ctx.program_id);
    let accounts: Vec<_> = ctx
        .accounts
        .iter()
        .map(|a| convert_account(fbb, a))
        .collect();
    let accounts_off = fbb.create_vector(&accounts);

    let instr_accounts: Vec<_> = ctx
        .instr_accounts
        .iter()
        .map(|ia| convert_instr_account(fbb, ia))
        .collect();
    let instr_accounts_off = fbb.create_vector(&instr_accounts);

    let instr_data_off = fbb.create_vector(&ctx.data);

    let features_off = ctx
        .epoch_context
        .as_ref()
        .and_then(|epoch_ctx| epoch_ctx.features.as_ref())
        .and_then(|fs| convert_feature_set(fbb, fs));

    fbs_instr::InstrContext::create(
        fbb,
        &fbs_instr::InstrContextArgs {
            program_id: Some(&program_id),
            account_states: Some(accounts_off),
            instr_accounts: Some(instr_accounts_off),
            instr_data: Some(instr_data_off),
            cu_avail: ctx.cu_avail,
            features: features_off,
        },
    )
}

fn convert_return_data<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    rd: &pb::ReturnData,
) -> flatbuffers::WIPOffset<fbs_vm::ReturnData<'a>> {
    let program_id = convert_pubkey(&rd.program_id);
    let data_off = fbb.create_vector(&rd.data);
    fbs_vm::ReturnData::create(
        fbb,
        &fbs_vm::ReturnDataArgs {
            program_id: Some(&program_id),
            data: Some(data_off),
        },
    )
}

fn convert_vm_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    vm_ctx: &pb::VmContext,
) -> flatbuffers::WIPOffset<fbs_vm::VmContext<'a>> {
    let rodata_off = fbb.create_vector(&vm_ctx.rodata);
    let return_data_off = vm_ctx
        .return_data
        .as_ref()
        .map(|rd| convert_return_data(fbb, rd));

    let calldests_off = fbb.create_vector(&vm_ctx.call_whitelist);

    fbs_vm::VmContext::create(
        fbb,
        &fbs_vm::VmContextArgs {
            rodata: Some(rodata_off),
            heap_max: vm_ctx.heap_max,
            rodata_text_section_offset: vm_ctx.rodata_text_section_offset,
            rodata_text_section_length: vm_ctx.rodata_text_section_length,
            return_data: return_data_off,
            sbpf_version: vm_ctx.sbpf_version as u8,
            r0: vm_ctx.r0,
            r1: vm_ctx.r1,
            r2: vm_ctx.r2,
            r3: vm_ctx.r3,
            r4: vm_ctx.r4,
            r5: vm_ctx.r5,
            r6: vm_ctx.r6,
            r7: vm_ctx.r7,
            r8: vm_ctx.r8,
            r9: vm_ctx.r9,
            r10: vm_ctx.r10,
            r11: vm_ctx.r11,
            calldests: Some(calldests_off),
            entry_pc: vm_ctx.entry_pc,
        },
    )
}

fn convert_syscall_invocation<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    inv: &pb::SyscallInvocation,
) -> flatbuffers::WIPOffset<fbs_vm::SyscallInvocation<'a>> {
    let function_name = String::from_utf8_lossy(&inv.function_name);
    let function_name_off = fbb.create_string(&function_name);
    let heap_prefix_off = fbb.create_vector(&inv.heap_prefix);
    let stack_prefix_off = fbb.create_vector(&inv.stack_prefix);

    fbs_vm::SyscallInvocation::create(
        fbb,
        &fbs_vm::SyscallInvocationArgs {
            function_name: Some(function_name_off),
            heap_prefix: Some(heap_prefix_off),
            stack_prefix: Some(stack_prefix_off),
        },
    )
}

fn convert_syscall_context<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    ctx: &pb::SyscallContext,
) -> flatbuffers::WIPOffset<fbs_vm::SyscallContext<'a>> {
    let instr_ctx_off = ctx
        .instr_ctx
        .as_ref()
        .map(|ic| convert_instr_context(fbb, ic));

    let vm_ctx_off = ctx.vm_ctx.as_ref().map(|vmc| convert_vm_context(fbb, vmc));

    let syscall_inv_off = ctx
        .syscall_invocation
        .as_ref()
        .map(|si| convert_syscall_invocation(fbb, si));

    fbs_vm::SyscallContext::create(
        fbb,
        &fbs_vm::SyscallContextArgs {
            instr_ctx: instr_ctx_off,
            vm_ctx: vm_ctx_off,
            syscall_invocation: syscall_inv_off,
        },
    )
}

fn convert_input_data_region<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    region: &pb::InputDataRegion,
) -> flatbuffers::WIPOffset<fbs_vm::InputDataRegion<'a>> {
    let content_off = fbb.create_vector(&region.content);
    fbs_vm::InputDataRegion::create(
        fbb,
        &fbs_vm::InputDataRegionArgs {
            offset: region.offset,
            is_writable: region.is_writable,
            content: Some(content_off),
        },
    )
}

fn convert_syscall_effects<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    effects: &pb::SyscallEffects,
) -> flatbuffers::WIPOffset<fbs_vm::SyscallEffects<'a>> {
    let heap_off = fbb.create_vector(&effects.heap);
    let stack_off = fbb.create_vector(&effects.stack);
    let rodata_off = fbb.create_vector(&effects.rodata);
    let log_str = String::from_utf8_lossy(&effects.log);
    let log_off = fbb.create_string(&log_str);
    let empty_log = fbb.create_string("");

    let input_data_regions: Vec<_> = effects
        .input_data_regions
        .iter()
        .map(|r| convert_input_data_region(fbb, r))
        .collect();
    let input_data_regions_off = fbb.create_vector(&input_data_regions);

    fbs_vm::SyscallEffects::create(
        fbb,
        &fbs_vm::SyscallEffectsArgs {
            r0: effects.r0,
            r1: effects.r1,
            r2: effects.r2,
            r3: effects.r3,
            r4: effects.r4,
            r5: effects.r5,
            r6: effects.r6,
            r7: effects.r7,
            r8: effects.r8,
            r9: effects.r9,
            r10: effects.r10,
            err_code: effects.error as i8,
            err_kind: fbs_vm::ErrKind(effects.error_kind as u8),
            cu_avail: effects.cu_avail,
            pc: effects.pc,
            frame_count: effects.frame_count,
            heap: Some(heap_off),
            stack: Some(stack_off),
            rodata: Some(rodata_off),
            input_data_regions: Some(input_data_regions_off),
            log: if log_str.is_empty() {
                Some(empty_log)
            } else {
                Some(log_off)
            },
        },
    )
}

fn convert_file(input_path: &PathBuf, output_path: &PathBuf) -> io::Result<()> {
    // Read protobuf file
    let pb_data = fs::read(input_path)?;
    let pb_fixture = pb::SyscallFixture::decode(&pb_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Convert to FlatBuffer
    let mut fbb = FlatBufferBuilder::with_capacity(1 << 20); // 1MB initial capacity

    let input_off = pb_fixture
        .input
        .as_ref()
        .map(|ctx| convert_syscall_context(&mut fbb, ctx));

    let output_off = pb_fixture
        .output
        .as_ref()
        .map(|eff| convert_syscall_effects(&mut fbb, eff));

    let metadata_off = pb_fixture.metadata.as_ref().map(|meta| {
        let entrypoint_off = fbb.create_string(&meta.fn_entrypoint);
        fbs_meta::FixtureMetadata::create(
            &mut fbb,
            &fbs_meta::FixtureMetadataArgs {
                fn_entrypoint: Some(entrypoint_off),
            },
        )
    });

    let fixture = fbs_vm::SyscallFixture::create(
        &mut fbb,
        &fbs_vm::SyscallFixtureArgs {
            input: input_off,
            output: output_off,
            metadata: metadata_off,
        },
    );

    fbb.finish_minimal(fixture);

    // Write to output file
    fs::write(output_path, fbb.finished_data())?;

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <output_dir> <input_files...>", args[0]);
        eprintln!("  output_dir: Directory to write converted FlatBuffer files");
        eprintln!("  input_files: One or more protobuf fixture files to convert");
        std::process::exit(1);
    }

    let output_dir = PathBuf::from(&args[1]);
    let input_files = &args[2..];

    // Create output directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&output_dir) {
        eprintln!("Failed to create output directory: {}", e);
        std::process::exit(1);
    }

    let mut total = 0;
    let mut success = 0;
    let mut failed = 0;

    for input_file in input_files {
        let input_path = PathBuf::from(input_file);
        total += 1;

        // Generate output filename
        let output_filename = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| format!("{}.fix", n.trim_end_matches(".fix")))
            .unwrap_or_else(|| format!("output_{}.fix", total));

        let output_path = output_dir.join(output_filename);

        match convert_file(&input_path, &output_path) {
            Ok(_) => {
                success += 1;
            }
            Err(e) => {
                eprintln!("Failed to convert {}: {}", input_file, e);
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
