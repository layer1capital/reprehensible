// "Ne" is short for Network Endian

use crate::pow_header::PowHeader;
use crate::DatagramHead;
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

    /// write self into dest and return rest, if self is too large to fit in dest, return None
    fn put(self, dest: &mut [u8]) -> Option<&mut [u8]> {
        let ne = self.to_ne();
        let ne = ne.as_ref();
        if ne.len() > dest.len() {
            None
        } else {
            let (head, tail) = dest.split_at_mut(ne.len());
            head.copy_from_slice(&ne);
            Some(tail)
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

impl Ne for DatagramHead {
    type B = Box<[u8]>;

    fn to_ne(self) -> Self::B {
        let mut ret = [0u8; 104];
        debug_assert_eq!(ret.len(), size_of::<DatagramHead>());
        let DatagramHead {
            destination_pk,
            source_pk,
            nonce,
            mac,
        } = self;
        {
            let mut rest = destination_pk.put(&mut ret).unwrap();
            let mut rest = source_pk.put(&mut rest).unwrap();
            let mut rest = nonce.put(&mut rest).unwrap();
            let rest = mac.put(&mut rest).unwrap();
            debug_assert_eq!(rest.len(), 0);
        }
        Box::new(ret)
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let (destination_pk, rest) = PublicKey::pick(src).unwrap();
        let (source_pk, rest) = PublicKey::pick(rest).unwrap();
        let (nonce, rest) = Nonce::pick(rest).unwrap();
        let (mac, _rest) = Tag::pick(rest).unwrap();
        DatagramHead {
            destination_pk,
            source_pk,
            nonce,
            mac,
        }
    }
}

impl Ne for PowHeader {
    type B = [u8; 32];

    fn to_ne(self) -> Self::B {
        let mut ret = [0u8; 32];
        debug_assert_eq!(ret.len(), size_of::<Self>());
        let PowHeader {
            pow_time_nanos,
            proof_of_work,
        } = self;
        {
            let mut rest = pow_time_nanos.put(&mut ret).unwrap();
            let rest = proof_of_work.put(&mut rest).unwrap();
            debug_assert_eq!(rest.len(), 0);
        }
        ret
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let (pow_time_nanos, rest) = u128::pick(src).unwrap();
        let (proof_of_work, _rest) = u128::pick(rest).unwrap();
        PowHeader {
            pow_time_nanos,
            proof_of_work,
        }
    }
}

/// Swap order of bytes if this is a little endian machine.
fn toggle_ne(bytes: &mut [u8]) {
    if cfg!(target_endian = "little") {
        bytes.reverse();
    }
}
