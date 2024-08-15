use solana_program_runtime::solana_rbpf::{
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion, MemoryState},
};

use crate::proto::InputDataRegion;

/* From a vector of InputDataRegions, setup MemoryRegion objects and
push into regions vector. Lifetime of the data is pegged to the
lifetime of the InputDataRegion itself since so no copies are made. */
pub fn setup_input_regions(
    regions: &mut Vec<MemoryRegion>,
    input_data_regions: &mut Vec<InputDataRegion>,
) {
    let mut input_data_off: u64 = 0;
    for input_data_region in input_data_regions {
        if input_data_region.content.len() == 0 {
            continue; // follow Agave, skip empty regions
        }
        if input_data_region.is_writable {
            regions.push(MemoryRegion::new_writable(
                input_data_region.content.as_mut_slice(),
                ebpf::MM_INPUT_START + input_data_off,
            ));
        } else {
            regions.push(MemoryRegion::new_readonly(
                input_data_region.content.as_slice(),
                ebpf::MM_INPUT_START + input_data_off,
            ));
        }
        input_data_off += input_data_region.content.len() as u64;
    }
}

/* From a MemoryMapping, extract the input data regions and convert
them into InputDataRegions. The regions themselves are not copied,
so be mindful of lifetimes. */
pub fn extract_input_data_regions<'a>(mapping: &'a MemoryMapping<'a>) -> Vec<InputDataRegion> {
    // Find first region(*) starting at MM_INPUT_START
    // Then iterate over the regions and collect the input data regions
    // until the end of the regions list.
    // * Regions are sorted by vm address.
    mapping
        .get_regions()
        .iter()
        .skip_while(|region| region.vm_addr < ebpf::MM_INPUT_START)
        .map(|region| InputDataRegion {
            content: unsafe {
                std::slice::from_raw_parts(region.host_addr.get() as *const u8, region.len as usize)
                    .to_vec()
            },
            offset: region.vm_addr - ebpf::MM_INPUT_START,
            is_writable: region.state.get() == MemoryState::Writable.into(),
        })
        .collect()
}
