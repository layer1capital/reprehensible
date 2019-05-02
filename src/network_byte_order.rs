// "Ne" is short for Network Endian

use byteorder::{ByteOrder, NetworkEndian};
use rust_sodium::crypto::box_::{Nonce, PublicKey, SecretKey, Tag};
use std::convert::AsRef;
use std::convert::TryInto;
use std::mem::size_of;

/// Serialize from/to network endian encoded bytes.
/// Does not work for variable length types.
pub trait Ne: std::marker::Sized {
    type B: AsRef<[u8]>;

    fn to_ne(self) -> Self::B;

    /// Should panic if src.len() != size_of::<Self>().
    fn from_ne_unchecked(src: &[u8]) -> Self;

    fn from_ne(src: &[u8]) -> Option<Self> {
        debug_assert_eq!(size_of::<Self>(), size_of::<Self::B>());
        if src.len() != size_of::<Self>() {
            None
        } else {
            debug_assert_eq!(
                size_of::<Self>(),
                Self::from_ne_unchecked(src).to_ne().as_ref().len()
            );
            Some(Self::from_ne_unchecked(src))
        }
    }

    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        if src.len() < size_of::<Self>() {
            None
        } else {
            let (head, tail) = src.split_at(size_of::<Self>());
            Some((Self::from_ne_unchecked(head), tail))
        }
    }
}

impl Ne for Nonce {
    type B = [u8; 24];

    fn to_ne(mut self) -> Self::B {
        toggle_ne(&mut self.0);
        self.0
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let mut slef = Self(src.try_into().unwrap());
        toggle_ne(&mut slef.0);
        slef
    }
}

impl Ne for PublicKey {
    type B = [u8; 32];

    fn to_ne(mut self) -> Self::B {
        toggle_ne(&mut self.0);
        self.0
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let mut slef = Self(src.try_into().unwrap());
        toggle_ne(&mut slef.0);
        slef
    }
}

impl Ne for SecretKey {
    type B = [u8; 32];

    fn to_ne(mut self) -> Self::B {
        toggle_ne(&mut self.0);
        self.0
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let mut slef = Self(src.try_into().unwrap());
        toggle_ne(&mut slef.0);
        slef
    }
}

impl Ne for Tag {
    type B = [u8; 16];

    fn to_ne(mut self) -> Self::B {
        toggle_ne(&mut self.0);
        self.0
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let mut slef = Self(src.try_into().unwrap());
        toggle_ne(&mut slef.0);
        slef
    }
}

impl Ne for u128 {
    type B = [u8; 16];

    fn to_ne(self) -> Self::B {
        let mut ret = [0u8; 16];
        NetworkEndian::write_u128(&mut ret, self);
        ret
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        NetworkEndian::read_u128(&src)
    }
}

/// Swap order of bytes if this is a little endian machine.
fn toggle_ne(bytes: &mut [u8]) {
    if cfg!(target_endian = "little") {
        bytes.reverse();
    }
}
