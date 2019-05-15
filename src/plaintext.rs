use crate::common::{deserialize_be, serialize_be};
use core::marker::PhantomData;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// A plaintext series of bytes. Ready to be deserialized to a T.                                                                                      
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Plaintext<T> {
    pub plaintext: Vec<u8>,
    pub _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Plaintext<T> {
    pub fn serialize(t: &T) -> bincode::Result<Self> {
        Ok(Plaintext {
            plaintext: serialize_be(t)?,
            _spook: PhantomData,
        })
    }

    pub fn deserialize(&self) -> bincode::Result<T> {
        deserialize_be::<T>(&self.plaintext)
    }
}
