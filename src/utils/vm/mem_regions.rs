use solana_program_runtime::solana_rbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    ebpf::HOST_ALIGN,
    memory_region::{MemoryMapping, MemoryRegion, MemoryState},
};

use crate::proto::InputDataRegion;

/* From a vector of InputDataRegions, setup MemoryRegion objects and
push into regions vector. Lifetime of the data is pegged to the
lifetime of the InputDataRegion itself since so no copies are made. */
pub fn setup_input_regions(
    regions: &mut Vec<MemoryRegion>,
    aligned_regions: &mut Vec<AlignedMemory<HOST_ALIGN>>,
    input_data_regions: &Vec<InputDataRegion>,
) {
    let mut input_data_off: u64 = 0;
    for input_data_region in input_data_regions {
        if input_data_region.content.is_empty() {
            continue; // follow Agave, skip empty regions
        }
        let mut mem = AlignedMemory::<HOST_ALIGN>::from(&input_data_region.content);
        if input_data_region.is_writable {
            regions.push(MemoryRegion::new_writable(
                mem.as_slice_mut(),
                ebpf::MM_INPUT_START + input_data_off,
            ));
        } else {
            regions.push(MemoryRegion::new_readonly(
                mem.as_slice(),
                ebpf::MM_INPUT_START + input_data_off,
            ));
        }
        aligned_regions.push(mem);
        input_data_off += input_data_region.content.len() as u64;
    }
}

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
