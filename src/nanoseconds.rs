use serde::{Deserialize, Serialize};
use shrinkwraprs::Shrinkwrap;

#[derive(Shrinkwrap, Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct Nanoseconds(u128);
