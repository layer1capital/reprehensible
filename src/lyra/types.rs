//! lyra (randomly named)

use crate::isle::Isle;
use crate::locked::Locked;
use crate::lyra::*;
use channel::{ChannelGrant, ChannelId, ChannelRequest};
use serde::{Deserialize, Serialize};

/// Lyra provides:
/// |                      |         |
/// | -                    | -       |
/// | Encryption           | yes     |
/// | Authentication       | yes     |
/// | DOS Resistance       | no      |
/// | Forward Secrecy      | yes     |
/// | Stateless Datagrams  | no      |
/// | Ordering             | no      |
/// | Reliability          | no      |
/// | Multiplexing         | yes     |
/// | Replay Protection    | partial |
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum Lyra<T> {
    /// Sent from the initiator to create a session
    RequestChannel(Isle<ChannelRequest>),
    /// Sent as a reply to RequestChannel
    GrantChannel(Isle<ChannelGrant>),
    /// Data sent to a supposedly already open channel
    ChannelData(ChannelData<T>),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ChannelData<T> {
    pub channel_id: ChannelId,
    pub locked_data: Locked<T>,
}
