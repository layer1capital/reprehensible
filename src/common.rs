use serde::{de::DeserializeOwned, Serialize};

pub fn deserialize_be<T: DeserializeOwned>(bs: &[u8]) -> bincode::Result<T> {
    bincode_cfg_be().deserialize(bs)
}

pub fn serialize_be<T: Serialize>(t: &T) -> bincode::Result<Vec<u8>> {
    bincode_cfg_be().serialize(t)
}

fn bincode_cfg_be() -> bincode::Config {
    let mut cfg = bincode::config();
    cfg.big_endian();
    cfg
}
