use crate::common::{serialize_be, SerializeFailed};
use serde::Serialize;
use sha2::digest::{Digest, FixedOutput};
use sha2::Sha256;

pub trait Sha256Ext {
    fn input_serializable<T: Serialize>(&mut self, t: &T) -> Result<(), SerializeFailed>;
    fn result_array(self) -> [u8; 32];
}

impl Sha256Ext for Sha256 {
    fn input_serializable<T: Serialize>(&mut self, t: &T) -> Result<(), SerializeFailed> {
        let bytes = serialize_be(t)?;
        self.input(&bytes);
        Ok(())
    }

    fn result_array(self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(self.fixed_result().as_ref());
        ret
    }
}
