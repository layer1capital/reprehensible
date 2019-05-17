use crate::invalid::Invalid;
use crate::locked::Locked;
use crate::lyra::*;
use crate::sha_ext::Sha256Ext;
use core::marker::PhantomData;
use rust_sodium::crypto::secretbox::Key;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{digest::Digest, Sha256};
use types::EphemeralSecret256;

/// Interesting property, channel can be transfered to another host, effectively giving the other
/// host ability to read and write messages on the channel.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct Channel<T> {
    shared_secret: Key,
    _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Channel<T> {
    pub fn create(a: &EphemeralSecret256, b: &EphemeralSecret256) -> Channel<T> {
        Channel {
            shared_secret: a ^ b,
            _spook: PhantomData,
        }
    }

    pub fn id(&self) -> ChannelId {
        /// a salted hash of the channel secret is used to uniquely identify the channel
        const SALT: &str = "f60fc7125eeb7ef5507c2a0d872be8d446c9bd8ebe41037a4001b3bf79de6a35";
        let salted_hash_of_secret = Sha256::new()
            .chain(SALT)
            .chain(&self.shared_secret.0)
            .result_array();
        ChannelId {
            salted_hash_of_secret,
        }
    }

    pub fn open(&self, message: Locked<T>) -> Result<T, Invalid> {
        message.open(&self.shared_secret)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ChannelId {
    /// The key is secret, but the salted sha256 hash of the key is not.
    salted_hash_of_secret: [u8; 32],
}
