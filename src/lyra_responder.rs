use crate::invalid::Invalid;
use crate::isle::Isle;
use crate::lyra::{ChannelData, FinalizeOpenChannel, InitiateOpenChannel, Lyra};
use core::marker::PhantomData;
use lru_cache::LruCache;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use rust_sodium::crypto::secretbox::Key;

pub struct Responder<T> {
    sk: SecretKey,
    ephemeral_secret: [u8; 32],
    channels: LruCache<[u8; 32], Key>,
    _spook: PhantomData<T>,
}

impl<T> Responder<T> {
    pub fn accept(&mut self, lyra: Lyra<T>) -> AcceptResult<T> {
        match lyra {
            Lyra::InitiateOpen(initiate) => self.accept_open_request(initiate).into(),
            Lyra::FinalizeOpen(_) => AcceptResult::Drop, // finalize requests are ignored
            Lyra::ChannelData(dat) => self.accept_channel(dat),
        }
    }

    fn accept_open_request(
        &mut self,
        init_request: Isle<InitiateOpenChannel>,
    ) -> Result<Isle<FinalizeOpenChannel>, Invalid> {
        let (source_pk, request) = init_request.open(&self.sk)?;
        let finalize: FinalizeOpenChannel =
            self.accept_open_request_decrypted(&request, &source_pk);
        Ok(Isle::seal(&source_pk, &self.sk, finalize)
            .expect("Got an err serializing, a FinalizeOpenChannel to memory."))
    }

    /// accept channel init after it has been decrypted
    fn accept_open_request_decrypted(
        &mut self,
        init_request: &InitiateOpenChannel,
        source_pk: &PublicKey,
    ) -> FinalizeOpenChannel {
        // Derive a random number from
        // (source_pk, self.ephmeral_secret, init_request.initiator_random)
        // FinalizeOpenChannel
        unimplemented!()
    }

    fn accept_channel(&mut self, isle: ChannelData<T>) -> AcceptResult<T> {
        unimplemented!()
    }
}

pub enum AcceptResult<T> {
    /// datagram should be ignored
    Drop,
    /// datagram was a channel initiation from public key. reply with this value to complete the
    /// initiation
    DoReply(Isle<FinalizeOpenChannel>),
    /// recieved message on an established channel
    Message(Message<T>),
}

pub struct Message<T> {
    source: PublicKey,
    channel: [u8; 32],
    plaintext: T,
}

impl<T> From<Result<Isle<FinalizeOpenChannel>, Invalid>> for AcceptResult<T> {
    fn from(r: Result<Isle<FinalizeOpenChannel>, Invalid>) -> AcceptResult<T> {
        match r {
            Ok(isle) => AcceptResult::DoReply(isle),
            Err(_) => AcceptResult::Drop,
        }
    }
}

impl<T> From<Result<Message<T>, Invalid>> for AcceptResult<T> {
    fn from(r: Result<Message<T>, Invalid>) -> AcceptResult<T> {
        match r {
            Ok(m) => AcceptResult::Message(m),
            Err(_) => AcceptResult::Drop,
        }
    }
}
