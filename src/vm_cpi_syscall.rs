use crate::{
    load_builtins, proto::{AcctState, CpiAccountMeta, CpiContext, CpiInstr, InstrAcct, SyscallEffects}, utils::{self, vm::STACK_SIZE}, InstrContext
};
use prost::Message;
use solana_bpf_loader_program::syscalls::{
  create_program_runtime_environment_v1
};
use solana_log_collector::LogCollector;
use std::{ffi::c_int, sync::Arc};
use solana_program_runtime::{
    invoke_context::{EnvironmentConfig, InvokeContext},
    loaded_programs::ProgramCacheForTxBatch,
    solana_rbpf::{
        ebpf::{self, MM_INPUT_START},
        memory_region::{MemoryMapping, MemoryRegion, AccessType},
        program::{BuiltinProgram, SBPFVersion},
        vm::{Config, EbpfVm},  
    },
    sysvar_cache::SysvarCache
};
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_sdk::{signer::Signer, transaction_context::{TransactionAccount, TransactionContext}};
use solana_sdk::account::AccountSharedData;
use solana_sdk::sysvar::rent::Rent;
use std::{slice, vec, alloc::Layout};



struct SimpleAllocator {
    start: u64,
    ptr: *mut u8,
    end: u64,
    vm_offset: u64,
}

impl SimpleAllocator{
  pub fn new(start: u64, size: u64, vm_offset: u64) -> Self {
    SimpleAllocator {
      start,
      ptr: start as *mut u8,
      end: start + size,
      vm_offset,
    }
  }

  pub fn alloc(&mut self, layout: Layout) -> VmPtr {

    let align = layout.align();
    let size = layout.size();
    let align_offset = if self.ptr.align_offset(align) == 0 {
      0
    } else {
      align - self.ptr.align_offset(align)
    };
    let new_ptr = unsafe { self.ptr.add(align_offset) };
    let new_end = unsafe { new_ptr.add(size) };
    if new_end as u64 > self.end {
      panic!("Out of memory");
    }
    self.ptr = new_end;
    VmPtr {
      haddr: new_ptr,
      vaddr: self.to_vm_ptr(new_ptr),
      len: size,
    }
    
  }
  fn to_vm_ptr(&self, ptr: *mut u8) -> u64 {
    ptr as u64 - self.start + self.vm_offset
  }

}


struct VmPtr{
  haddr:  *mut u8,
  vaddr: u64,
  len: usize,
}

trait CpiInstrLoader {
  type CPIInstr;
  type AccMeta;
  type AccInfo;

  fn setup_acc_meta(&self, acc_meta: &mut Self::AccMeta, acc_meta_ctx: &CpiAccountMeta, alloc: &mut SimpleAllocator) -> bool;
  fn setup_acc_info(&self, acc_info: &mut Self::AccInfo, acc_info_ctx: &AcctState, alloc: &mut SimpleAllocator) -> bool;
  fn setup_cpi_instr(&self, callee_id: &VmPtr, acc_metas: &VmPtr, data: &VmPtr, alloc: &mut SimpleAllocator) -> VmPtr;
}

/// Rust representation of C ABI
struct CpiInstrLoaderC;
#[repr(C)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
}
#[derive(Debug)]
#[repr(C)]
struct SolAccountMeta {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
}

#[derive(Debug)]
#[repr(C)]
struct SolAccountInfo {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
}

impl CpiInstrLoader for CpiInstrLoaderC {
    type CPIInstr = SolInstruction;
    type AccMeta = SolAccountMeta;
    type AccInfo = SolAccountInfo;

    fn setup_acc_meta(&self, acc_meta: &mut Self::AccMeta, acc_meta_ctx: &CpiAccountMeta, alloc: &mut SimpleAllocator) -> bool{
      acc_meta.is_signer = acc_meta_ctx.is_signer;
      acc_meta.is_writable = acc_meta_ctx.is_writable;

      // allocate space for pubkey and copy from context
      let pubkey_ctx = &acc_meta_ctx.pubkey;
      unsafe {
        let pubkey_ptr = alloc.alloc(Layout::from_size_align(pubkey_ctx.len(), 1).unwrap());
        pubkey_ptr.haddr.copy_from_nonoverlapping(
          pubkey_ctx.as_ptr(),
          pubkey_ctx.len(),
        );
        acc_meta.pubkey_addr = pubkey_ptr.vaddr;
      }
      true 
    }

    fn setup_acc_info(&self, acc_info: &mut Self::AccInfo, acc_info_ctx: &AcctState, alloc: &mut SimpleAllocator) -> bool {
      acc_info.is_signer = acc_info_ctx.is_signer;
      acc_info.is_writable = acc_info_ctx.is_writable;
      acc_info.executable = acc_info_ctx.executable;
      acc_info.rent_epoch = acc_info_ctx.rent_epoch;

      // allocate space for pubkey and copy from context
      let owner_key = &acc_info_ctx.owner;
      unsafe {
        let pubkey_ptr = alloc.alloc(Layout::from_size_align(owner_key.len(), 1).unwrap());
        pubkey_ptr.haddr.copy_from_nonoverlapping(
          owner_key.as_ptr(),
          owner_key.len(),
        );
        acc_info.owner_addr = pubkey_ptr.vaddr;
      }
      
      // allocate space for owner pubkey and copy from context
      let pubkey_ctx = &acc_info_ctx.address;
      unsafe {
        let pubkey_ptr = alloc.alloc(Layout::from_size_align(pubkey_ctx.len(), 1).unwrap());
        pubkey_ptr.haddr.copy_from_nonoverlapping(
          pubkey_ctx.as_ptr(),
          pubkey_ctx.len(),
        );
        acc_info.key_addr = pubkey_ptr.vaddr;
      }

      // allocate space for lamports and copy from context
      let lamports_ctx = &acc_info_ctx.lamports;
      unsafe {
        let lamports_ptr = alloc.alloc(Layout::from_size_align(std::mem::size_of::<u64>(), 1).unwrap());
        lamports_ptr.haddr.copy_from_nonoverlapping(
          lamports_ctx as *const u64 as *const u8,
          8
        );
        acc_info.lamports_addr = lamports_ptr.vaddr;
      }

      // allocate space for data and copy from context
      // FIXME: data should be in input region
      let data_ctx = &acc_info_ctx.data;
      unsafe {
        let data_ptr = alloc.alloc(Layout::from_size_align(data_ctx.len(), 1).unwrap());
        data_ptr.haddr.copy_from_nonoverlapping(
          data_ctx.as_ptr(),
          data_ctx.len(),
        );
        acc_info.data_addr = data_ptr.vaddr;
        acc_info.data_len = data_ctx.len() as u64;
      }
      true
    }

    fn setup_cpi_instr(&self, callee_id: &VmPtr, acc_metas: &VmPtr, data: &VmPtr, alloc: &mut SimpleAllocator) -> VmPtr {
      let cpi_instr = SolInstruction {
        program_id_addr: callee_id.vaddr,
        accounts_addr: acc_metas.vaddr,
        accounts_len: acc_metas.len as u64,
        data_addr: data.vaddr,
        data_len: data.len as u64,
      };
      let cpi_instr_ptr = alloc.alloc(Layout::new::<SolInstruction>());
      unsafe {
        cpi_instr_ptr.haddr.copy_from_nonoverlapping(
          &cpi_instr as *const _ as *const u8,
          cpi_instr_ptr.len,
        );
      }
      cpi_instr_ptr
    }
}

fn setup_cpi<L>(
    cpi_instr_ctx: &CpiInstr,
    vm: &mut  EbpfVm<InvokeContext>,
    loader: &L) -> bool 
where
    L: CpiInstrLoader 
    {
    let mut mmap = &vm.memory_mapping;
    let mut heap_region =   mmap.region(AccessType::Store, ebpf::MM_HEAP_START).unwrap();
    let mut stack_region =  mmap.region(AccessType::Store, ebpf::MM_STACK_START).unwrap();

    let mut heap_ptr = heap_region.host_addr.get() as *mut u8;
    let mut stack_ptr = stack_region.host_addr.get() as *mut u8;

    let mut heap_alloc = SimpleAllocator::new(heap_region.host_addr.get(), heap_region.len  , ebpf::MM_HEAP_START);
    let mut stack_alloc = SimpleAllocator::new(stack_region.host_addr.get(), stack_region.len, ebpf::MM_STACK_START);

    unsafe {
    // CPI Instr
    // Callee Program ID (to stack)
    let callee_program_id = &cpi_instr_ctx.callee_program_id;
    let callee_program_id_ptr = stack_alloc.alloc(Layout::from_size_align(callee_program_id.len(), 1).unwrap());
    callee_program_id_ptr.haddr.copy_from_nonoverlapping(
      callee_program_id.as_ptr(),
      callee_program_id.len(),
    );    

    // Account Metas (to heap)
    let acc_metas_ctx = &cpi_instr_ctx.acct_metas;
    // get slice in heap for accounts
    let accounts_meta_cnt = acc_metas_ctx.len();
    
    // CHECK IF ALIGNMENT SCRERWS THINGS UP
    let accounts_meta_ptr = heap_alloc.alloc(Layout::array::<L::AccMeta>(accounts_meta_cnt).unwrap());
    let mut accounts_meta_slice = slice::from_raw_parts_mut(accounts_meta_ptr.haddr as *mut L::AccMeta, accounts_meta_cnt);

    for (i, acc_meta_ctx) in acc_metas_ctx.iter().enumerate() {
        if !loader.setup_acc_meta( &mut accounts_meta_slice[i], acc_meta_ctx, &mut heap_alloc) {
            return false;
        }
    }

    // Instruction Data (to heap)
    let data = &cpi_instr_ctx.data;
    let data_ptr = heap_alloc.alloc(Layout::from_size_align(data.len(), 1).unwrap());
    data_ptr.haddr.copy_from_nonoverlapping(data.as_ptr(), data.len());   

    // Setup CPI Instr
    let cpi_instr_ptr = loader.setup_cpi_instr(&callee_program_id_ptr, &accounts_meta_ptr, &data_ptr, &mut heap_alloc);
    vm.registers[1] = cpi_instr_ptr.vaddr;
    // End CPI Instr

    // Account Info
    let acc_infos = &cpi_instr_ctx.accounts;
    let acc_infos_cnt = acc_infos.len();

    let acc_infos_ptr = heap_alloc.alloc(Layout::array::<L::AccInfo>(acc_infos_cnt).unwrap());
    let acc_infos_slice = slice::from_raw_parts_mut(acc_infos_ptr.haddr as *mut L::AccInfo, acc_infos_cnt);

    for (i, acc_info_ctx) in acc_infos.iter().enumerate() {
        if !loader.setup_acc_info(&mut acc_infos_slice[i], acc_info_ctx, &mut heap_alloc) {
            return false;
        }
    }

    vm.registers[2] = acc_infos_ptr.vaddr;
    vm.registers[3] = acc_infos_cnt as u64;

    // End Account Info
    // type SignersSeeds = &[&[&[u8]]];
    // Signers Seeds (array of u8 slices)
    let signers_seeds = &cpi_instr_ctx.signers_seeds;
    let signers_seeds_cnt = signers_seeds.len();
    let signers_seeds_ptr = heap_alloc.alloc(Layout::array::<&[&[u8]]>(signers_seeds_cnt).unwrap());
    let signers_seeds_slice = slice::from_raw_parts_mut(signers_seeds_ptr.haddr as *mut &[&[u8]], signers_seeds_cnt);

    for (i, signers_seeds_ctx) in signers_seeds.iter().enumerate() {
        let seeds_cnt = signers_seeds_ctx.seeds.len();
        let seeds_ptr = heap_alloc.alloc(Layout::array::<&[u8]>(seeds_cnt).unwrap());
        let seeds_slice = slice::from_raw_parts_mut(seeds_ptr.haddr as *mut &[u8], seeds_cnt);
        for (j, seed_ctx) in signers_seeds_ctx.seeds.iter().enumerate() {
            let seed_ptr = heap_alloc.alloc(Layout::from_size_align(seed_ctx.len(), 1).unwrap());
            seed_ptr.haddr.copy_from_nonoverlapping(seed_ctx.as_ptr(), seed_ctx.len());
            seeds_slice[j] = std::slice::from_raw_parts(seed_ptr.haddr, seed_ctx.len());
        }
        signers_seeds_slice[i] = seeds_slice;
    }
    vm.registers[4] = signers_seeds_ptr.vaddr;
    vm.registers[5] = signers_seeds_cnt as u64;  

    // End Signers Seeds
  } // end unsafe

  true
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let cpi_context = match CpiContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };

    // let syscall_effects = match execute_vm_syscall(syscall_context) {
    //     Some(v) => v,
    //     None => return 0,
    // };
    // let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    // let out_vec = syscall_effects.encode_to_vec();
    // if out_vec.len() > out_slice.len() {
    //     return 0;
    // }
    // out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    // *out_psz = out_vec.len() as u64;

    1
}

fn execute_cpi_syscall(input: CpiContext) -> Option<SyscallEffects> {
    let instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;
    let feature_set = instr_ctx.feature_set;
    let cpi_instr_ctx = input.cpi_instr?;

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
        Arc::new(feature_set.clone()),
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

    // TODO: support different versions
    let sbpf_version = &SBPFVersion::V1;

    // Set up memory mapping
    let vm_ctx = input.vm_ctx.unwrap();
    let rodata = vm_ctx.rodata;
    let mut stack = vec![0; STACK_SIZE];
    let heap_max = vm_ctx.heap_max;
    let mut heap = vec![0; heap_max as usize];
    let mut regions = vec![
        MemoryRegion::new_readonly(&rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
    ];
    let mut input_data_regions = vm_ctx.input_data_regions.clone();
    for input_data_region in &mut input_data_regions {
        if input_data_region.is_writable {
            regions.push(MemoryRegion::new_writable(
                input_data_region.content.as_mut_slice(),
                MM_INPUT_START + input_data_region.offset,
            ));
        } else {
            regions.push(MemoryRegion::new_readonly(
                input_data_region.content.as_slice(),
                MM_INPUT_START + input_data_region.offset,
            ));
        }
    }
    let config = &Config {
        aligned_memory_mapping: true,
        enable_sbpf_v2: true,
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
    vm.registers[0] = vm_ctx.r0;
    vm.registers[1] = vm_ctx.r1;
    vm.registers[2] = vm_ctx.r2;
    vm.registers[3] = vm_ctx.r3;
    vm.registers[4] = vm_ctx.r4;
    vm.registers[5] = vm_ctx.r5;
    vm.registers[6] = vm_ctx.r6;
    vm.registers[7] = vm_ctx.r7;
    vm.registers[8] = vm_ctx.r8;
    vm.registers[9] = vm_ctx.r9;
    vm.registers[10] = vm_ctx.r10;
    vm.registers[11] = vm_ctx.r11;

    // TODO: LOAD CPI INSTR HERE
    let cpi_loader = CpiInstrLoaderC;
    setup_cpi(&cpi_instr_ctx, &mut vm, &cpi_loader);


    let program_runtime_environment_v1 =
        create_program_runtime_environment_v1(&feature_set, &ComputeBudget::default(), true, false)
            .unwrap();
    
    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry()
        .lookup_by_name("sol_invoke_signed_c".as_bytes())?;

    vm.invoke_function(syscall_func);


    None
    // Some(SyscallEffects {
    //     log_messages: vec![],
    //     account_deps: vec![],
    //     program_deps: vec![],
    //     updated_accounts: vec![],
    //     heap_delta: 0,
    //     instruction_errors: vec![],
    // })
}