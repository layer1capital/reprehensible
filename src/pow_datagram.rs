use crate::network_byte_order::Ne;
use crate::pow_header::PowHeader;
use crate::Datagram;

/// A datagram with a timestamped Pow tag over it's source and destination public keys.
pub struct PowDatagram {
    pub pow_header: PowHeader,
    pub datagram: Datagram,
}

impl PowDatagram {
    pub fn score(&self) -> u32 {
        self.pow_header.pow_score(
            &self.datagram.head.destination_pk,
            &self.datagram.head.source_pk,
        )
    }

    pub fn parse(raw: &[u8]) -> Option<PowDatagram> {
        let (pow_header, rest) = PowHeader::pick(raw)?;
        let datagram = Datagram::parse(&rest)?;
        Some(PowDatagram {
            pow_header,
            datagram,
        })
    }

    pub fn serialize(self) -> Vec<u8> {
        let PowDatagram {
            pow_header,
            datagram,
        } = self;
        let mut ret = pow_header.to_ne().as_ref().to_vec();
        ret.extend(datagram.serialize());
        ret
    }
}
