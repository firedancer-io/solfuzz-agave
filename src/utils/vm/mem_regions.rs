use solana_program_runtime::solana_rbpf::{
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion, MemoryState},
};

use crate::proto::InputDataRegion;

/* From a MemoryMapping, extract the input data regions and convert
them into InputDataRegions. The regions themselves are not copied,
so be mindful of lifetimes. */
pub fn extract_input_data_regions<'a>(mapping: &'a MemoryMapping<'a>) -> Vec<InputDataRegion> {
    match mapping {
        MemoryMapping::Aligned(mapping) => {
            // regions in AlignedMemoryMapping are sorted by vm_addr
            mapping
                .get_regions()
                .iter()
                .skip_while(|region| region.vm_addr < ebpf::MM_INPUT_START)
                .map(mem_region_to_input_data_region)
                .collect()
        }
        MemoryMapping::Unaligned(mapping) => {
            // regions are in eytzinger order, so we need to collect and sort them
            let mut input_regions: Vec<InputDataRegion> = mapping
                .get_regions()
                .iter()
                .filter(|region| region.vm_addr >= ebpf::MM_INPUT_START)
                .map(mem_region_to_input_data_region)
                .collect();

            // Sort the vector by `vm_addr`
            input_regions.sort_by_key(|region| region.offset);
            input_regions
        }
        _ => vec![],
    }
}

pub fn copy_memory_prefix(dst: &mut [u8], src: &[u8]) {
    let size = dst.len().min(src.len());
    dst[..size].copy_from_slice(&src[..size]);
}

fn mem_region_to_input_data_region(region: &MemoryRegion) -> InputDataRegion {
    InputDataRegion {
        content: unsafe {
            std::slice::from_raw_parts(region.host_addr.get() as *const u8, region.len as usize)
                .to_vec()
        },
        offset: region.vm_addr - ebpf::MM_INPUT_START,
        is_writable: region.state.get() == MemoryState::Writable,
    }
}
