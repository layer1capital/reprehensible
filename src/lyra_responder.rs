use crate::lyra::{FinalizeOpenChannel, Lyra};
use crate::plaintext::Plaintext;
use core::marker::PhantomData;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use sealed::Sealed;

struct Responder<T> {
    _spook: PhantomData<T>,
}

impl<T> Responder<T> {
    fn accept(&mut self, lyra: Lyra<T>) -> AcceptResult<T> {
        unimplemented!()
    }
}

enum AcceptResult<T> {
    /// datagram should be ignored
    Drop,
    /// datagram was a channel initiation from public key. reply with this value to complete the
    /// initiation
    DoReply(PublicKey, Sealed<Sealed<FinalizeOpenChannel>>),
    /// recieved message on channel. First field represents the channel id, second, the message
    Message([u8; 32], Plaintext<T>),
}
