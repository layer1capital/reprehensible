use crate::common::{serialize_be, SerializeFailed};
use serde::Serialize;
use sha2::digest::Digest;
use sha2::Sha256;

trait Sha256Ext {
    fn input_serializable<T: Serialize>(&mut self, t: &T) -> Result<(), SerializeFailed>;
}

impl Sha256Ext for Sha256 {
    fn input_serializable<T: Serialize>(&mut self, t: &T) -> Result<(), SerializeFailed> {
        let bytes = serialize_be(t)?;
        self.input(&bytes);
        Ok(())
    }
}
