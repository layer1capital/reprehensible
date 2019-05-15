//! Data encrypted with a secret 256 bit key.

use crate::plaintext::Plaintext;
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
    pub fn open(mut self, secret_key: &Key) -> Option<Plaintext<T>> {
        open_detached(&mut self.cyphertext, &self.tag, &self.nonce, secret_key).ok()?;
        Some(Plaintext {
            plaintext: self.cyphertext,
            _spook: PhantomData,
        })
    }

    pub fn seal(secret_key: &Key, mut plaintext: Plaintext<T>) -> Locked<T> {
        let nonce = gen_nonce();
        let tag = seal_detached(&mut plaintext.plaintext, &nonce, &secret_key);
        Locked {
            nonce,
            tag,
            cyphertext: plaintext.plaintext,
            _spook: PhantomData,
        }
    }
}
