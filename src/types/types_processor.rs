use crate::proto::TypeEffects;
use crate::types::memory_representation_serializer::MemoryRepresentationSerializer;
use bincode::Options;
use serde::Serialize;

#[allow(dead_code)]
pub fn process_type<T: Serialize + serde::de::DeserializeOwned>(
    bincode_slice: &[u8],
) -> Option<TypeEffects> {
    let config = bincode::config::DefaultOptions::new()
        .with_limit(10_000_000) // Limit to 10MB (adjust as needed)
        .with_fixint_encoding()
        .allow_trailing_bytes();

    let res = config.deserialize::<T>(&bincode_slice[1..]);
    let typ = match res {
        Ok(h) => h,
        Err(_err) => {
            return Some(TypeEffects {
                result: 1,
                ..Default::default()
            });
        }
    };

    let mut ser = MemoryRepresentationSerializer::new();
    let out = typ.serialize(&mut ser);
    match out {
        Ok(_) => {}
        Err(_e) => {
            return Some(TypeEffects {
                result: 1,
                ..Default::default()
            });
        }
    }

    let yaml_str = serde_yaml::to_string(&typ).unwrap_or_default();

    Some(TypeEffects {
        result: 0,
        representation: ser.output.into_bytes(),
        yaml: yaml_str.as_bytes().to_vec(),
    })
}
