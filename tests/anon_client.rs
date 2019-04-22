// use reprehensible::*;

#[test]
#[ignore]
fn anon() {}

// struct ReprehensibleAnon {
//     ephemeral_sk: SecretKey,
//     static_sk: SecretKey,
// }

// impl ReprehensibleAnon {
//     fn create(static_sk: SecretKey) -> Self {
//         ReprehensibleAnon {
//             ephemeral_sk: random_sk(),
//             static_sk,
//         }
//     }

//     fn send<'a>(&self, dest_pk: &PublicKey, plaintext: &'a mut Vec<u8>) -> Datagram<'a> {
//         SessionKeys::compute(&self.static_sk, &dest_pk)
//             .seal(self.static_sk, gen_nonce(), plaintext)
//             .serialize()
//     }

//     fn recv<'a>(&self, dg: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
//         SessionKeys::compute(&self.sk, &dg.peer_pk).open(dg)
//     }

//     fn pk(&self) -> PublicKey {
//         self.sk.public_key()
//     }
// }
