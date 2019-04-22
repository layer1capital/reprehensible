use reprehensible::*;

pub fn copy_datagram<'a>(other: &Datagram, buf: &'a mut [u8]) -> Datagram<'a> {
    let buf = buf.split_at_mut(other.encrypted_payload.len()).0;
    buf.copy_from_slice(other.encrypted_payload);
    Datagram {
        peer_pk: other.peer_pk,
        nonce: other.nonce,
        tag: other.tag,
        encrypted_payload: buf,
    }
}
