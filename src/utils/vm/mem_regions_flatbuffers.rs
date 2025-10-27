use itertools::Itertools;
use solana_sbpf::{
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion},
};

use crate::vm_generated;

/* From a MemoryMapping, extract the input data regions and convert
them into InputDataRegions. Takes a reference to a mutable builder which
will perform allocations to create a vector of flatbuffer-type input
data regions. */
pub fn extract_input_data_regions<'a, 'b>(
    mapping: &'a MemoryMapping<'a>,
    builder: &mut flatbuffers::FlatBufferBuilder<'b>,
) -> Vec<flatbuffers::WIPOffset<vm_generated::InputDataRegion<'b>>> {
    match mapping {
        MemoryMapping::Aligned(_mapping) => {
            // regions in AlignedMemoryMapping are sorted by vm_addr
            mapping
                .get_regions()
                .iter()
                .skip_while(|region| region.vm_addr < ebpf::MM_INPUT_START)
                .map(|region| mem_region_to_input_data_region(region, builder))
                .collect::<Vec<_>>()
        }
        MemoryMapping::Unaligned(_mapping) => {
            // regions are in eytzinger order, so we need to collect and sort them
            mapping
                .get_regions()
                .iter()
                .filter(|region| region.vm_addr >= ebpf::MM_INPUT_START)
                .sorted_by_key(|region| region.vm_addr)
                .map(|region| mem_region_to_input_data_region(region, builder))
                .collect::<Vec<_>>()
        }
        _ => vec![],
    }
}

pub fn copy_memory_prefix(dst: &mut [u8], src: &[u8]) {
    let size = dst.len().min(src.len());
    dst[..size].copy_from_slice(&src[..size]);
}

fn mem_region_to_input_data_region<'a>(
    region: &MemoryRegion,
    builder: &mut flatbuffers::FlatBufferBuilder<'a>,
) -> flatbuffers::WIPOffset<vm_generated::InputDataRegion<'a>> {
    let content_output = builder.create_vector(unsafe {
        std::slice::from_raw_parts(region.host_addr as *const u8, region.len as usize)
    });
    vm_generated::InputDataRegion::create(
        builder,
        &vm_generated::InputDataRegionArgs {
            content: Some(content_output),
            offset: region.vm_addr.saturating_sub(ebpf::MM_INPUT_START),
            is_writable: region.writable,
        },
    )
}
