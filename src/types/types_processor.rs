use crate::proto::TypeEffects;
use crate::types::memory_representation_serializer::MemoryRepresentationSerializer;
use serde::Serialize;

use bincode::Options;

#[allow(dead_code)]
pub fn process_type<T: Serialize + serde::de::DeserializeOwned>(
    bincode_slice: &[u8],
) -> Option<TypeEffects> {
    let config = bincode::DefaultOptions::new().with_limit(10 * 1024 * 1024);

    let typ: T = if let Ok(h) = config.deserialize(&bincode_slice[1..]) {
        h
    } else {
        return Some(TypeEffects {
            result: 1,
            ..Default::default()
        });
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
