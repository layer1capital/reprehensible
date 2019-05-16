use serde::{de::DeserializeOwned, Serialize};

pub fn deserialize_be<T: DeserializeOwned>(bs: &[u8]) -> Result<T, DeserializeFailed> {
    bincode_cfg_be()
        .deserialize(bs)
        .map_err(|_| DeserializeFailed {})
}

pub fn serialize_be<T: Serialize>(t: &T) -> Result<Vec<u8>, SerializeFailed> {
    bincode_cfg_be()
        .serialize(t)
        .map_err(|_| SerializeFailed {})
}

fn bincode_cfg_be() -> bincode::Config {
    let mut cfg = bincode::config();
    cfg.big_endian();
    cfg
}

/// Value could not be encrypted because in-memory serializaition failed.
#[derive(PartialEq, Clone, Debug)]
pub struct SerializeFailed;

#[derive(PartialEq, Clone, Debug)]
pub struct DeserializeFailed;
