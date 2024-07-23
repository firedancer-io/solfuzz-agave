use crate::{
    load_builtins, proto::{ CpiSnapshot, Cpiabi, SyscallEffects},
    utils::{self, vm::STACK_SIZE},
    InstrContext
};
use prost::Message;
use solana_bpf_loader_program::syscalls::{
  create_program_runtime_environment_v1
};
use solana_log_collector::LogCollector;
use solana_svm::program_loader;
use std::{collections::HashSet, ffi::c_int, sync::Arc};
use solana_program_runtime::{
    invoke_context::{BpfAllocator, EnvironmentConfig, InvokeContext, SerializedAccountMetadata, SyscallContext},
    loaded_programs::{ProgramCacheForTxBatch, ProgramRuntimeEnvironments},
    solana_rbpf::{
        ebpf::{self, MM_INPUT_START},
        error::StableResult,
        memory_region::{AccessType, MemoryMapping, MemoryRegion},
        program::{BuiltinProgram, SBPFVersion},
        vm::{Config, ContextObject, EbpfVm}  
    },
    sysvar_cache::SysvarCache
};
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_sdk::{pubkey::Pubkey, transaction_context::{IndexOfAccount, TransactionAccount, TransactionContext}};
use solana_sdk::account::AccountSharedData;
use solana_sdk::sysvar::rent::Rent;
use std::{slice, vec, alloc::Layout};


#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let cpi_context = match CpiSnapshot::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let syscall_effects = match execute_cpi_syscall(cpi_context) {
        Some(v) => v,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = syscall_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

fn execute_cpi_syscall(input: CpiSnapshot) -> Option<SyscallEffects> {

    let abi = input.abi().clone();
    let instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;
    // let feature_set = instr_ctx.feature_set;


    let mut transaction_accounts =
        Vec::<TransactionAccount>::with_capacity(instr_ctx.accounts.len() + 1);
    #[allow(deprecated)]
    instr_ctx
        .accounts
        .clone()
        .into_iter()
        .map(|(pubkey, account)| (pubkey, AccountSharedData::from(account)))
        .for_each(|x| transaction_accounts.push(x));

    let compute_budget = ComputeBudget {
        compute_unit_limit: instr_ctx.cu_avail,
        ..ComputeBudget::default()
    };
    let mut transaction_context = TransactionContext::new(
        transaction_accounts.clone(),
        Rent::default(),
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
    );

    // sigh ... What is this mess?
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    load_builtins(&mut program_cache_for_tx_batch);

    let program_runtime_environment_v1 =
        create_program_runtime_environment_v1(&instr_ctx.feature_set, &ComputeBudget::default(), true, false)
            .unwrap();

    // let environments = ProgramRuntimeEnvironments{
    //     program_runtime_v1: Arc::new(program_runtime_environment_v1),
    //     ..ProgramRuntimeEnvironments::default()
    // };

    // let mut newly_loaded_programs = HashSet::<Pubkey>::new();
    // for acc in &instr_ctx.accounts {
    //     // FD rejects duplicate account loads
    //     if !newly_loaded_programs.insert(acc.0) {
    //         return None;
    //     }

    //     if acc.1.executable && program_cache_for_tx_batch.find(&acc.0).is_none() {
    //         // load_program_with_pubkey expects the owner to be one of the bpf loader
    //         if !solana_sdk::loader_v4::check_id(&acc.1.owner)
    //             && !solana_sdk::bpf_loader_deprecated::check_id(&acc.1.owner)
    //             && !solana_sdk::bpf_loader::check_id(&acc.1.owner)
    //             && !solana_sdk::bpf_loader_upgradeable::check_id(&acc.1.owner)
    //         {
    //             continue;
    //         }
    //         // https://github.com/anza-xyz/agave/blob/af6930da3a99fd0409d3accd9bbe449d82725bd6/svm/src/program_loader.rs#L124
    //         /* pub fn load_program_with_pubkey<CB: TransactionProcessingCallback, FG: ForkGraph>(
    //             callbacks: &CB,
    //             program_cache: &ProgramCache<FG>,
    //             pubkey: &Pubkey,
    //             slot: Slot,
    //             effective_epoch: Epoch,
    //             epoch_schedule: &EpochSchedule,
    //             reload: bool,
    //         ) -> Option<Arc<ProgramCacheEntry>> { */
    //         if let Some(loaded_program) = program_loader::load_program_with_pubkey(
    //             &instr_ctx,
    //             &environments,
    //             &acc.0,
    //             10, // FIXME: slot
    //             false,
    //         ) {
    //             program_cache_for_tx_batch.replenish(acc.0, loaded_program);
    //         }
    //     }
    // }

    let sysvar_cache = SysvarCache::default();
    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = sysvar_cache
        .get_recent_blockhashes()
        .ok()
        .and_then(|x| (*x).last().cloned())
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    let environment_config = EnvironmentConfig::new(
        blockhash,
        None,
        None,
        Arc::new(instr_ctx.feature_set.clone()),
        lamports_per_signature,
        &sysvar_cache,
    );
    let log_collector = LogCollector::new_ref();
    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(log_collector.clone()),
        compute_budget,
    );

    // Setup syscall context in the invoke context

    // Setup the instruction context in the invoke context
    let instr = &instr_ctx.instruction;
    let instr_accounts = crate::get_instr_accounts(
        &transaction_accounts,
        &instr.accounts
    );

    let caller_instr_ctx = invoke_context.transaction_context
        .get_next_instruction_context()
        .unwrap();

    let program_idx_in_txn = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == instr_ctx.instruction.program_id)?
        as IndexOfAccount;

    caller_instr_ctx.configure(&[program_idx_in_txn], instr_accounts.as_slice(), &instr.data);

    match invoke_context.push(){
        Ok(_) => (),
        Err(_) => eprintln!("Failed to push invoke context")
    }
    invoke_context.set_syscall_context(SyscallContext {
        allocator: BpfAllocator::new(instr_ctx.heap_size as u64),
        accounts_metadata: vec![SerializedAccountMetadata{
            original_data_len: 0,
            vm_data_addr: 0,
            vm_key_addr: 0,
            vm_owner_addr: 0,
            vm_lamports_addr: 0,
        };instr_accounts.len()], // TODO: accounts metadata for direct mapping support
        trace_log: Vec::new(),
    }).unwrap();

    // TODO: support different versions
    let sbpf_version = &SBPFVersion::V1;

    // Set up memory mapping
    let rodata = input.ro_region;

    let mut stack = input.stack;
    stack.resize(STACK_SIZE, 0);

    let mut heap = input.heap;
    heap.resize(instr_ctx.heap_size as usize, 0);
    
    // FIXME: Do it the "Agave" way (i.e, individual sub regions for each account info with custom perms)
    let mut input_region = input.input_region;

    let regions = vec![
        MemoryRegion::new_readonly(&rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(&mut input_region, MM_INPUT_START),
    ];


    let config = &Config {
        aligned_memory_mapping: true,
        enable_sbpf_v2: false,
        ..Config::default()
    };
    let memory_mapping = MemoryMapping::new(regions, config, sbpf_version).unwrap();

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
    let mut vm = EbpfVm::new(
        loader,
        &SBPFVersion::V1,
        &mut invoke_context,
        memory_mapping,
        STACK_SIZE,
    );
    vm.registers[1] = input.instruction_va;
    vm.registers[2] = input.account_infos_va;
    vm.registers[3] = input.account_infos_cnt;
    vm.registers[4] = input.signers_seeds_va;
    vm.registers[5] = input.signers_seeds_cnt;


    
    let syscall_fn_name = match abi {
      Cpiabi::Rust => "sol_invoke_signed_rust".as_bytes(),
      Cpiabi::C => "sol_invoke_signed_c".as_bytes(),
      _ => "sol_invoke_signed_rust".as_bytes() // FIXME: should be an error
    };

    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry()
        .lookup_by_name(syscall_fn_name)?;
    
    vm.invoke_function(syscall_func);

    // Print error if any
    if let StableResult::Err(ref ebpf_error) = vm.program_result {
        let e = ebpf_error.clone();
        eprintln!("Error: {:?}", e);
    }


    Some( SyscallEffects{
      error: match vm.program_result {
        StableResult::Ok(_) => 0,
        StableResult::Err(ref ebpf_error) => 
            utils::vm::err_map::get_fd_vm_err_code(ebpf_error).into()
      },
      // Register 0 doesn't seem to contain the result, maybe we're missing some code from agave.
      // Regardless, the result is available in vm.program_result, so we can return it from there.
      r0: match vm.program_result {
          StableResult::Ok(n) => n,
          StableResult::Err(_) => 0,
      },
      cu_avail: vm.context_object_pointer.get_remaining(),
      frame_count: vm.call_depth,
      // TODO
      heap: vec![],
      stack: vec![],
      inputdata: vec![],
      log: vec![]
    })
}