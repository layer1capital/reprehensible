mod common;
mod invalid;
mod isle;
mod locked;
mod lyra;
mod lyra_responder;
mod nanoseconds;
mod sealed;
mod sha_ext;
use nanoseconds::Nanoseconds;
use sealed::Sealed;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Datagram {
    timestamp: Nanoseconds,
    message: Sealed<Vec<u8>>,
}
