// This is an auto-generated file. To add entries, edit fd_types.json
use crate::types::types_generated::TYPE_PROCESSORS;
use crate::proto::{TypeContext, TypeEffects};
use prost::Message;

use std::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_type_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let type_ctx = match TypeContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let type_effects = match execute_type(type_ctx) {
        Some(effects) => effects,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = type_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

pub fn execute_type(input: TypeContext) -> Option<TypeEffects> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if input.content.is_empty() {
            return None;
        }

        let bincode_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(input.content.as_ptr(), input.content.len()) };

        TYPE_PROCESSORS
            .get(&bincode_slice[0])
            .map(|processor| processor(bincode_slice))
            .unwrap_or_else(|| {
                eprintln!("Invalid type ID: {}", bincode_slice[0]);
                None
            })
    }));

    // Handle any panic that might have occurred
    match result {
        Ok(effects) => effects,
        Err(_) => Some(TypeEffects {
            result: 1,
            ..Default::default()
        }),
    }
}
