use solana_sbpf::{
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion},
};

use protosol::protos::InputDataRegion;

/* From a MemoryMapping, extract the input data regions and convert
them into InputDataRegions. The regions themselves are not copied,
so be mindful of lifetimes. */
pub fn extract_input_data_regions(mapping: &MemoryMapping) -> Vec<InputDataRegion> {
    // MemoryMapping internally can be Aligned (regions sorted by vm_addr) or
    // Unaligned (eytzinger order). Collect-then-sort handles both layouts.
    let mut input_regions: Vec<InputDataRegion> = mapping
        .get_regions()
        .iter()
        .filter(|region| region.vm_addr >= ebpf::MM_INPUT_START)
        .map(mem_region_to_input_data_region)
        .collect();
    input_regions.sort_by_key(|region| region.offset);
    input_regions
}

pub fn copy_memory_prefix(dst: &mut [u8], src: &[u8]) {
    let size = dst.len().min(src.len());
    dst[..size].copy_from_slice(&src[..size]);
}

fn mem_region_to_input_data_region(region: &MemoryRegion) -> InputDataRegion {
    InputDataRegion {
        content: unsafe {
            std::slice::from_raw_parts(region.host_addr as *const u8, region.len as usize).to_vec()
        },
        offset: region.vm_addr.saturating_sub(ebpf::MM_INPUT_START),
        is_writable: region.writable,
    }
}
