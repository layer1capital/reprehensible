use crate::isle::Isle;
use crate::lyra::{ChannelData, EphemeralSecret256, GrantChannel, Lyra, RequestChannel};
use crate::lyra_channel::{Channel, ChannelId};

use lru::LruCache;
use rust_sodium::crypto::box_::SecretKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub struct Responder<T> {
    sk: SecretKey,
    channels: LruCache<ChannelId, Channel<T>>,
}

impl<T: Serialize + DeserializeOwned> Responder<T> {
    pub fn accept(&mut self, lyra: Lyra<T>) -> AcceptResult<T> {
        match lyra {
            Lyra::InitiateOpen(initiate) => self.accept_open(initiate).into(),
            Lyra::FinalizeOpen(_) => AcceptResult::Drop, // finalize requests are ignored
            Lyra::ChannelData(dat) => self.accept_channel(dat).into(),
        }
    }

    fn accept_open(&mut self, init_request: Isle<RequestChannel>) -> Option<Isle<GrantChannel>> {
        let (source_pk, request) = init_request.open(&self.sk).ok()?;
        let finalize = self.accept_open_decrypted(&request);
        let ret = Isle::seal(&source_pk, &self.sk, &finalize).ok();
        debug_assert!(ret.is_some());
        ret
    }

    /// accept channel init after it has been decrypted
    fn accept_open_decrypted(&mut self, init_request: &RequestChannel) -> GrantChannel {
        let initiator_random_hash = init_request.initiator_random.id();
        let responder_random = EphemeralSecret256::random();

        let channel = Channel::create(&init_request.initiator_random, &responder_random);
        let _ = self.channels.put(channel.id(), channel);

        GrantChannel {
            initiator_random_hash,
            responder_random,
        }
    }

    /// decrypt ChannelData into a Message, return None if encrypted message is invalid or if referenced
    /// channel not known
    ///
    /// # Known issue
    ///
    /// An mitm attacker can reflect channel data back to the sender, the sender will accept the packet as
    /// if it came from the other party.
    fn accept_channel(&mut self, cd: ChannelData<T>) -> Option<Message<T>> {
        let channel = self.channels.get(&cd.channel_id)?;
        let plaintext: T = channel.open(cd.locked_data).ok()?;
        Some(Message {
            channel_id: cd.channel_id,
            plaintext,
        })
    }
}

pub enum AcceptResult<T> {
    /// datagram should be ignored
    Drop,
    /// datagram was a channel initiation from public key. reply with this value to complete the
    /// initiation
    DoReply(Isle<GrantChannel>),
    /// recieved message on an established channel
    Message(Message<T>),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Message<T> {
    channel_id: ChannelId,
    plaintext: T,
}

impl<T> From<Option<Isle<GrantChannel>>> for AcceptResult<T> {
    fn from(r: Option<Isle<GrantChannel>>) -> AcceptResult<T> {
        match r {
            Some(isle) => AcceptResult::DoReply(isle),
            None => AcceptResult::Drop,
        }
    }
}

impl<T> From<Option<Message<T>>> for AcceptResult<T> {
    fn from(r: Option<Message<T>>) -> AcceptResult<T> {
        match r {
            Some(m) => AcceptResult::Message(m),
            None => AcceptResult::Drop,
        }
    }
}
