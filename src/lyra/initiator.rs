use crate::isle::Isle;
use crate::lyra::*;
use channel::Channel;
use core::marker::PhantomData;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use types::{EphemeralSecret256, GrantChannel, RequestChannel};

use serde::{de::DeserializeOwned, Serialize};

/// tracks a channel open request
// Don't derive Deserialize here. We don't want the user accidentally sending a secret key.
pub struct EstablishingChannel<T> {
    initiator_random: EphemeralSecret256,
    _spook: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> EstablishingChannel<T> {
    /// Create a new channel
    pub fn random() -> EstablishingChannel<T> {
        EstablishingChannel {
            initiator_random: EphemeralSecret256::random(),
            _spook: PhantomData,
        }
    }

    /// Generate a channel creation request.
    /// Request will only be decryptable by destination_pk.
    pub fn request(
        &self,
        destination_pk: &PublicKey,
        origin_sk: &SecretKey,
    ) -> Isle<RequestChannel> {
        Isle::seal(
            destination_pk,
            origin_sk,
            &RequestChannel {
                initiator_random: self.initiator_random.clone(),
            },
        )
        .expect("In memory serialization of an RequestChannel failed.")
    }

    /// Check if fin was intended as a response to this channel request.
    fn matches(&self, fin: &GrantChannel) -> bool {
        self.initiator_random.id() == fin.initiator_random_hash
    }

    /// accept finalization from server to establish a channel
    ///
    /// Return None if fin does not target this request.
    pub fn finalize(self, fin: &GrantChannel) -> Option<Channel<T>> {
        if !self.matches(&fin) {
            None
        } else {
            Some(Channel::create(
                &self.initiator_random,
                &fin.responder_random,
            ))
        }
    }
}
