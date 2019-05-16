//! Data encrypted with a secret 256 bit key.

use crate::common::{deserialize_be, serialize_be, SerializeFailed};
use crate::invalid::Invalid;
use core::marker::PhantomData;
use rust_sodium::crypto::secretbox::{gen_nonce, open_detached, seal_detached, Key, Nonce, Tag};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Locked<T> {
    nonce: Nonce,
    tag: Tag,
    cyphertext: Vec<u8>,
    _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Locked<T> {
    pub fn open(mut self, secret_key: &Key) -> Result<T, Invalid> {
        open_detached(&mut self.cyphertext, &self.tag, &self.nonce, secret_key)
            .map_err(|_| Invalid::Decryption)?;
        Ok(deserialize_be(&self.cyphertext)?)
    }

    pub fn seal(secret_key: &Key, plaintext: &T) -> Result<Locked<T>, SerializeFailed> {
        let mut plaintext_raw = serialize_be(plaintext)?;
        let nonce = gen_nonce();
        let tag = seal_detached(&mut plaintext_raw, &nonce, &secret_key);
        Ok(Locked {
            nonce,
            tag,
            cyphertext: plaintext_raw,
            _spook: PhantomData,
        })
    }
}
