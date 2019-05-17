use crate::common::{deserialize_be, serialize_be, SerializeFailed};
use crate::invalid::Invalid;
use core::marker::PhantomData;
use rust_sodium::crypto::box_::{
    gen_nonce, open_detached_precomputed, precompute, seal_detached_precomputed, Nonce,
    PrecomputedKey, PublicKey, SecretKey, Tag,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Sealed<T> {
    /// Public key of sender.
    origin_pk: PublicKey,
    nonce: Nonce,
    /// Message authentication code.
    mac: Tag,
    /// A serialized, then encrypted T.
    cyphertext: Vec<u8>,
    _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Sealed<T> {
    pub fn open(self, destination_sk: &SecretKey) -> Result<T, Invalid> {
        let shared_secret = precompute(&self.origin_pk, destination_sk);
        self.open_precomputed(shared_secret)
    }

    fn open_precomputed(self, shared_secret: PrecomputedKey) -> Result<T, Invalid> {
        let Sealed {
            origin_pk,
            nonce,
            mac,
            mut cyphertext,
            _spook,
        } = self;
        let shared_send_secret = send_sk(shared_secret, &origin_pk);
        open_detached_precomputed(&mut cyphertext, &mac, &nonce, &shared_send_secret)
            .map_err(|_| Invalid::Decryption)?;
        let maybe_t = deserialize_be(&cyphertext);
        // clear plaintext from memory for extra security
        for b in cyphertext.iter_mut() {
            *b = 0;
        }
        Ok(maybe_t?)
    }

    pub fn seal(
        destination_pk: &PublicKey,
        origin_sk: &SecretKey,
        plaintext: &T,
    ) -> Result<Sealed<T>, SerializeFailed> {
        let shared_secret = precompute(&destination_pk, &origin_sk);
        let origin_pk = origin_sk.public_key();
        Sealed::seal_precomputed(origin_pk, shared_secret, plaintext)
    }

    fn seal_precomputed(
        origin_pk: PublicKey,
        shared_secret: PrecomputedKey,
        plaintext: &T,
    ) -> Result<Sealed<T>, SerializeFailed> {
        let mut plaintext = serialize_be(plaintext)?;
        let shared_send_secret = send_sk(shared_secret, &origin_pk);
        let nonce = gen_nonce();
        let mac = seal_detached_precomputed(&mut plaintext, &nonce, &shared_send_secret);
        Ok(Sealed {
            origin_pk,
            nonce,
            mac,
            cyphertext: plaintext,
            _spook: PhantomData,
        })
    }

    /// get unverified Public key of sender
    pub fn origin_pk(&self) -> &PublicKey {
        &self.origin_pk
    }
}

/// calculate the key to be used when sending from origin_pk
fn send_sk(shared_secret: PrecomputedKey, origin_pk: &PublicKey) -> PrecomputedKey {
    // Needs review by a cryptologist. Is xor safe to use here?
    PrecomputedKey(xor_bytes(shared_secret.0, &origin_pk.0))
}

fn xor_bytes(mut a: [u8; 32], b: &[u8; 32]) -> [u8; 32] {
    for (s, p) in a.iter_mut().zip(b.iter()) {
        *s ^= p;
    }
    a
}
