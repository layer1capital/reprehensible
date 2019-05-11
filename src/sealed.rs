use core::marker::PhantomData;
use rust_sodium::crypto::box_::{
    gen_nonce, open_detached_precomputed, precompute, seal_detached_precomputed, Nonce,
    PrecomputedKey, PublicKey, SecretKey, Tag,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Sealed<T: Serialize + DeserializeOwned> {
    /// Public key of receiver, potentially used for routing.
    destination_pk: PublicKey,
    /// Public key of sender.
    source_pk: PublicKey,
    nonce: Nonce,
    /// Message authentication code.
    mac: Tag,
    /// A serialized, then encrypted T.
    cyphertext: Vec<u8>,
    _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Sealed<T> {
    pub fn open(self, destination_sk: &SecretKey) -> Option<bincode::Result<T>> {
        let shared_secret = precompute(&self.source_pk, destination_sk);
        self.open_precomputed(shared_secret)
    }

    pub fn open_precomputed(self, shared_secret: PrecomputedKey) -> Option<bincode::Result<T>> {
        let Sealed {
            destination_pk,
            source_pk,
            nonce,
            mac,
            mut cyphertext,
            _spook,
        } = self;
        let shared_send_secret = send_sk(shared_secret, &source_pk);
        open_detached_precomputed(&mut cyphertext, &mac, &nonce, &shared_send_secret).ok()?;
        let ret = Some(deserialize_be::<T>(&cyphertext));

        /// clear unused decrypted text from memory
        for b in cyphertext.iter_mut() {
            *b = 0;
        }
        debug_assert!(cyphertext.iter().all(|b| b == &0));

        ret
    }

    pub fn seal(self, destination_sk: &SecretKey) -> Option<bincode::Result<T>> {
        let shared_secret = precompute(&self.source_pk, destination_sk);
        self.open_precomputed(shared_secret)
    }

    pub fn seal_precomputed(
        self,
        destination_pk: PublicKey,
        source_pk: PublicKey,
        shared_secret: PrecomputedKey,
        plaintext: &T,
    ) -> bincode::Result<Sealed<T>> {
        let mut plaintext: Vec<u8> = serialize_be(plaintext)?;
        let shared_send_secret = send_sk(shared_secret, &source_pk);
        let nonce = gen_nonce();
        let mac = seal_detached_precomputed(&mut plaintext, &nonce, &shared_send_secret);
        Ok(Sealed {
            destination_pk,
            source_pk,
            nonce,
            mac,
            cyphertext: plaintext,
            _spook: PhantomData,
        })
    }

    /// get Public key of receiver
    pub fn destination_pk(&self) -> &PublicKey {
        &self.destination_pk
    }

    /// get unverified Public key of sender
    pub fn source_pk(&self) -> &PublicKey {
        &self.source_pk
    }
}

// calculate the key to be used when sending from source_pk
fn send_sk(shared_secret: PrecomputedKey, source_pk: &PublicKey) -> PrecomputedKey {
    PrecomputedKey(xor_bytes(shared_secret.0, &source_pk.0))
}

fn xor_bytes(mut a: [u8; 32], b: &[u8; 32]) -> [u8; 32] {
    for (s, p) in a.iter_mut().zip(b.iter()) {
        *s ^= p;
    }
    a
}

fn deserialize_be<T: DeserializeOwned>(bs: &[u8]) -> bincode::Result<T> {
    bincode_cfg().deserialize(bs)
}

fn serialize_be<T: Serialize>(t: &T) -> bincode::Result<Vec<u8>> {
    bincode_cfg().serialize(t)
}

fn bincode_cfg() -> bincode::Config {
    let mut cfg = bincode::config();
    cfg.big_endian();
    cfg
}
