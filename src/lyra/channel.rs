use crate::invalid::Invalid;
use crate::locked::Locked;
use crate::lyra::*;
use crate::sha_ext::Sha256Ext;
use core::marker::PhantomData;
use ephemeral_secret::EphemeralSecret;
use rust_sodium::crypto::secretbox::Key;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{digest::Digest, Sha256};

/// Interesting property, channel can be transfered to another host, effectively giving the other
/// host ability to send messages on the channel.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Channel<T> {
    shared_secret: Key,
    _spook: PhantomData<T>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ChannelId([u8; 32]);

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ChannelRequest {
    initiator_random: EphemeralSecret,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ChannelRequestId([u8; 32]);

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ChannelGrant {
    channel_request_id: ChannelRequestId,
    responder_random: EphemeralSecret,
}

impl<T> Channel<T> {
    pub fn create(request: &ChannelRequest, grant: &ChannelGrant) -> Channel<T> {
        Channel {
            shared_secret: &request.initiator_random ^ &grant.responder_random,
            _spook: PhantomData,
        }
    }

    /// get the salted hash of the channel secret used to uniquely identify the channel
    pub fn id(&self) -> ChannelId {
        const SALT: &str = "f60fc7125eeb7ef5507c2a0d872be8d446c9bd8ebe41037a4001b3bf79de6a35";
        ChannelId(
            Sha256::new()
                .chain(SALT)
                .chain(&self.shared_secret.0)
                .result_array(),
        )
    }
}

impl<T: Serialize + DeserializeOwned> Channel<T> {
    pub fn open(&self, message: Locked<T>) -> Result<T, Invalid> {
        message.open(&self.shared_secret)
    }
}

impl ChannelRequest {
    pub fn grant<T>(&self) -> ChannelGrant {
        ChannelGrant {
            channel_request_id: self.id(),
            responder_random: EphemeralSecret::random(),
        }
    }

    /// The salted hash of an ephemeral secret is considered public.
    pub fn id(&self) -> ChannelRequestId {
        const SALT: &str = "3844437d53db02f90f435a1d7e5270878fc9e699c04b09f386de2e97ffcbc982";
        ChannelRequestId(
            Sha256::new()
                .chain(SALT)
                .chain(&self.initiator_random)
                .result_array(),
        )
    }
}
