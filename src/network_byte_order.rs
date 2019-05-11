// "Ne" is short for Network Endian

use crate::pow_datagram::PowDatagram;
use crate::pow_header::PowHeader;
use crate::{Datagram, DatagramHead};
use byteorder::{ByteOrder, NetworkEndian};
use rust_sodium::crypto::box_::{Nonce, PublicKey, SecretKey, Tag};
use std::convert::TryInto;
use std::marker::Sized;
use std::mem::size_of;

/// Serialize to network endian encoded bytes.
pub trait ToNe: Sized {
    /// Write self into dest and return rest, if self is too large to fit in dest, return None
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]>;

    /// Returns the size of self when serialized.
    /// Panics will occur If the return value of this function is too small.
    fn size(&self) -> usize;

    /// Serialize self to a Vec.
    ///
    /// # Panics
    ///
    /// This function will panic it the size reported by [`size`] is incorrect.
    fn serialize_to_vec(&self) -> Vec<u8> {
        let mut ret = vec![0u8; self.size()];
        let rest = self
            .put(&mut ret)
            .expect("object serialized was larger than reported");
        if !rest.is_empty() {
            panic!("object serialized was smaller than reported");
        }
        ret
    }
}

/// Serialize to/from network endian encoded bytes.
pub trait Ne: ToNe {
    /// Parse bytes as network endian. Return parsed value and unparsed bytes.
    /// If src is not long enough, return None.
    fn pick(src: &[u8]) -> Option<(Self, &[u8])>;
}

impl ToNe for Nonce {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        put_toggle_ne(&self.0, dest)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Ne for Nonce {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (mut head, rest) = take_sized::<[u8; 24]>(src)?;
        toggle_ne(&mut head);
        Some((Self(head), rest))
    }
}

impl ToNe for PublicKey {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        put_toggle_ne(&self.0, dest)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Ne for PublicKey {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (mut head, rest) = take_sized::<[u8; 32]>(src)?;
        toggle_ne(&mut head);
        Some((Self(head), rest))
    }
}

impl ToNe for SecretKey {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        put_toggle_ne(&self.0, dest)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Ne for SecretKey {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (mut head, rest) = take_sized::<[u8; 32]>(src)?;
        toggle_ne(&mut head);
        Some((Self(head), rest))
    }
}

impl ToNe for Tag {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        put_toggle_ne(&self.0, dest)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Ne for Tag {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (mut head, rest) = take_sized::<[u8; 16]>(src)?;
        toggle_ne(&mut head);
        Some((Self(head), rest))
    }
}

impl ToNe for u128 {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (mut head, rest) = safe_split_mut(dest, size_of::<Self>())?;
        NetworkEndian::write_u128(&mut head, *self);
        Some(rest)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Ne for u128 {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (head, rest) = take_sized::<[u8; 16]>(src)?;
        Some((NetworkEndian::read_u128(&head), rest))
    }
}

impl<T: ToNe> ToNe for &T {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        (*self).put(dest)
    }

    fn size(&self) -> usize {
        (*self).size()
    }
}

impl<T: ToNe, S: ToNe> ToNe for (T, S) {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (t, s) = self;
        let dest = t.put(dest)?;
        let dest = s.put(dest)?;
        Some(dest)
    }

    fn size(&self) -> usize {
        let (t, s) = self;
        ToNe::size(t) + ToNe::size(s)
    }
}

impl<T: Ne, S: Ne> Ne for (T, S) {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (t, src) = T::pick(src)?;
        let (s, src) = S::pick(src)?;
        Some(((t, s), src))
    }
}

impl<A: ToNe, B: ToNe, C: ToNe, D: ToNe> ToNe for (A, B, C, D) {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (a, b, c, d) = self;
        let dest = a.put(dest)?;
        let dest = b.put(dest)?;
        let dest = c.put(dest)?;
        let dest = d.put(dest)?;
        Some(dest)
    }

    fn size(&self) -> usize {
        let (a, b, c, d) = self;
        ToNe::size(a) + ToNe::size(b) + ToNe::size(c) + ToNe::size(d)
    }
}

impl<A: Ne, B: Ne, C: Ne, D: Ne> Ne for (A, B, C, D) {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let (a, src) = A::pick(src)?;
        let (b, src) = B::pick(src)?;
        let (c, src) = C::pick(src)?;
        let (d, src) = D::pick(src)?;
        Some(((a, b, c, d), src))
    }
}

impl ToNe for DatagramHead {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let DatagramHead {
            destination_pk,
            source_pk,
            nonce,
            mac,
        } = self;
        ToNe::put(&(destination_pk, source_pk, nonce, mac), dest)
    }

    fn size(&self) -> usize {
        let DatagramHead {
            destination_pk,
            source_pk,
            nonce,
            mac,
        } = self;
        ToNe::size(destination_pk) + ToNe::size(source_pk) + ToNe::size(nonce) + ToNe::size(mac)
    }
}

impl Ne for DatagramHead {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let ((destination_pk, source_pk, nonce, mac), rest) = Ne::pick(src)?;
        Some((
            DatagramHead {
                destination_pk,
                source_pk,
                nonce,
                mac,
            },
            rest,
        ))
    }
}

impl ToNe for PowHeader {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let PowHeader {
            pow_time_nanos,
            proof_of_work,
        } = self;
        ToNe::put(&(pow_time_nanos, proof_of_work), dest)
    }

    fn size(&self) -> usize {
        let PowHeader {
            pow_time_nanos,
            proof_of_work,
        } = self;
        ToNe::size(&(pow_time_nanos, proof_of_work))
    }
}

impl Ne for PowHeader {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let ((pow_time_nanos, proof_of_work), rest) = Ne::pick(src)?;
        Some((
            PowHeader {
                pow_time_nanos,
                proof_of_work,
            },
            rest,
        ))
    }
}

impl ToNe for Datagram {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let Datagram { head, cyphertext } = self;
        (head, cyphertext).put(dest)
    }

    fn size(&self) -> usize {
        let Datagram { head, cyphertext } = self;
        ToNe::size(&(head, cyphertext))
    }
}

impl Ne for Datagram {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let ((head, cyphertext), rest) = Ne::pick(src)?;
        Some((Datagram { head, cyphertext }, rest))
    }
}

impl ToNe for Vec<u8> {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        put(self.as_ref(), dest)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Ne for Vec<u8> {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        Some((src.to_vec(), &[]))
    }
}

impl ToNe for PowDatagram {
    fn put<'a>(&self, dest: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let PowDatagram {
            pow_header,
            datagram,
        } = self;
        ToNe::put(&(pow_header, datagram), dest)
    }

    fn size(&self) -> usize {
        let PowDatagram {
            pow_header,
            datagram,
        } = self;
        ToNe::size(&(pow_header, datagram))
    }
}

impl Ne for PowDatagram {
    fn pick(src: &[u8]) -> Option<(Self, &[u8])> {
        let ((pow_header, datagram), rest) = Ne::pick(src)?;
        Some((
            PowDatagram {
                pow_header,
                datagram,
            },
            rest,
        ))
    }
}

/// Swap order of bytes if this is a little endian machine.
fn toggle_ne(bytes: &mut [u8]) {
    if cfg!(target_endian = "little") {
        bytes.reverse();
    }
}

/// Split src at n index or None if src.len() < n.
fn safe_split(src: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    if src.len() >= n {
        Some(src.split_at(n))
    } else {
        None
    }
}

/// Split src at n index or None if src.len() < n.
fn safe_split_mut(src: &mut [u8], n: usize) -> Option<(&mut [u8], &mut [u8])> {
    if src.len() >= n {
        Some(src.split_at_mut(n))
    } else {
        None
    }
}

/// Split src on at n index or None if src.len() < n.
fn take_sized<'a, T>(src: &'a [u8]) -> Option<(T, &'a [u8])>
where
    &'a [u8]: TryInto<T>,
{
    let (head, tail) = safe_split(src, size_of::<T>())?;
    let ret = head.try_into().ok();
    debug_assert!(ret.is_some());
    Some((ret?, tail))
}

/// Write src into dest, return unwriten bytes or None if dest is not long enough.
fn put<'a>(src: &[u8], dest: &'a mut [u8]) -> Option<(&'a mut [u8])> {
    let (head, tail) = safe_split_mut(dest, src.len())?;
    head.copy_from_slice(src);
    Some(tail)
}

/// Same as put, but convert to network endian
fn put_toggle_ne<'a>(src: &[u8], dest: &'a mut [u8]) -> Option<(&'a mut [u8])> {
    let (head, tail) = safe_split_mut(dest, src.len())?;
    head.copy_from_slice(src);
    toggle_ne(head);
    Some(tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use rust_sodium::crypto::box_::{gen_keypair, gen_nonce};
    use std::fmt::Debug;

    fn ser<T: ToNe>(t: T) {
        t.serialize_to_vec();
    }

    fn ser_deser<T: Ne + PartialEq + Debug>(t: T) {
        let v = t.serialize_to_vec();
        let (t2, rest) = T::pick(&v).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(t, t2);
    }

    fn rand_vecu8() -> Vec<u8> {
        (0..(random::<usize>() % 265)).map(|_| random()).collect()
    }

    #[test]
    /// serialize, deserialize Nonce
    fn sd_nonce() {
        ser_deser(gen_nonce());
    }

    #[test]
    fn sd_pk() {
        ser_deser::<PublicKey>(gen_keypair().0);
    }

    #[test]
    fn sd_sk() {
        ser_deser::<SecretKey>(gen_keypair().1);
    }

    #[test]
    fn sd_tag() {
        ser_deser(Tag(random()));
    }

    #[test]
    fn sd_u128() {
        ser_deser::<u128>(random());
        ser::<&u128>(&random());
    }

    #[test]
    fn sd_2t() {
        ser_deser::<(u128, u128)>(random());
    }

    #[test]
    fn sd_4t() {
        ser_deser::<(u128, u128, u128, u128)>(random());
    }

    #[test]
    fn sd_dgh() {
        ser_deser(DatagramHead {
            destination_pk: PublicKey(random()),
            source_pk: PublicKey(random()),
            nonce: Nonce(random()),
            mac: Tag(random()),
        });
    }

    #[test]
    fn sd_ph() {
        ser_deser(PowHeader {
            pow_time_nanos: random(),
            proof_of_work: random(),
        });
    }

    #[test]
    fn sd_dg() {
        ser_deser(Datagram {
            head: DatagramHead {
                destination_pk: PublicKey(random()),
                source_pk: PublicKey(random()),
                nonce: Nonce(random()),
                mac: Tag(random()),
            },
            cyphertext: rand_vecu8(),
        });
    }

    #[test]
    fn sd_vu8() {
        ser_deser(rand_vecu8());
    }

    #[test]
    fn sd_pdg() {
        ser_deser(PowDatagram {
            pow_header: PowHeader {
                pow_time_nanos: random(),
                proof_of_work: random(),
            },
            datagram: Datagram {
                head: DatagramHead {
                    destination_pk: PublicKey(random()),
                    source_pk: PublicKey(random()),
                    nonce: Nonce(random()),
                    mac: Tag(random()),
                },
                cyphertext: rand_vecu8(),
            },
        });
    }
}
