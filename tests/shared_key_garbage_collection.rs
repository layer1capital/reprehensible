use reprehensible::*;
use std::collections::{BTreeMap, VecDeque};

// Problem:
// session_cache only grows. An attack may fill it, causing the server to run out of memory.
// The cache may also fill over time in the absence of attacks.

// Solution:
//

// To protect against a denile of service attack, it's recomended you combine this method
// with the one outlined in 'puzzle.rs'

#[test]
fn shared_key_one_call() {
    let mut server = ReprehensibleCache::create();
    let mut client = ReprehensibleCache::create();
    let mut hello = b"hello".to_owned();
    let datagram = client.send(&server.pk(), &mut hello);
    let datagram_decrypted = server.recv(datagram).unwrap();
    assert_eq!(datagram_decrypted.peer_pk().0, client.pk().0);
    assert_eq!(&datagram_decrypted.payload(), &b"hello");
}

#[test]
fn shared_key_garbage_collection() {
    let mut server = ReprehensibleCache::create();
    for i in 0..20 {
        let mut client = Reprehensible::create(random_sk());
        let mut hello = b"hello".to_owned();
        let datagram = client.send(&server.pk(), &mut hello);
        let datagram_decrypted = server.recv(datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk().0, client.pk().0);
        assert_eq!(&datagram_decrypted.payload(), &b"hello");

        assert_eq!(server.eviction_order.len(), (i + 1).min(10));
        assert_eq!(
            server.session_cache.len(),
            server.session_cache.iter().map(|_| 1).sum()
        );
    }
}

struct ReprehensibleCache {
    pub sk: SecretKey,
    /// the max nuber of entries - 1
    pub max_extra_cache: usize,
    pub session_cache: BTreeMap<PublicKey, SessionKeys>,
    pub eviction_order: VecDeque<PublicKey>,
}

impl ReprehensibleCache {
    fn create() -> Self {
        let max_extra_cache: usize = 10;
        ReprehensibleCache {
            sk: random_sk(),
            max_extra_cache,
            session_cache: BTreeMap::new(),
            eviction_order: VecDeque::with_capacity(max_extra_cache + 1),
        }
    }

    fn send<'a>(&mut self, dest_pk: &PublicKey, plaintext: &'a mut [u8]) -> Datagram<'a> {
        let self_pk = self.pk();
        self.session_keys(dest_pk)
            .seal(self_pk, gen_nonce(), plaintext)
    }

    fn recv<'a>(&mut self, dg: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        self.session_keys(&dg.peer_pk).open(dg)
    }

    fn pk(&self) -> PublicKey {
        self.sk.public_key()
    }

    fn session_keys(&mut self, peer_pk: &PublicKey) -> &SessionKeys {
        // check cache, if present, return item
        if self.session_cache.get(peer_pk).is_some() {
            return self.session_cache.get(peer_pk).unwrap();
        }

        // session keys were not cached, we must generate new ones

        // Make room by removing the oldest entry if nessesary.
        if self.eviction_order.len() >= self.max_extra_cache {
            debug_assert_eq!(self.eviction_order.len(), self.max_extra_cache);
            // Here we know that self.eviction_order.len() is at least 1

            // Connection to be evicted
            let toss = self.eviction_order.pop_back().unwrap();
            let toss_sks = self.session_cache.remove(&toss);
            debug_assert!(toss_sks.is_some());
            debug_assert_eq!(
                self.eviction_order.len() + 1,
                self.max_extra_cache,
                "We have room for exactly one more entry."
            );
        }

        self.eviction_order.push_front(peer_pk.clone());
        dbg!(self.eviction_order.len());
        dbg!(self.max_extra_cache);
        debug_assert!(self.eviction_order.len() <= self.max_extra_cache);
        let sks = SessionKeys::compute(&self.sk, peer_pk);
        self.session_cache.entry(*peer_pk).or_insert(sks)
    }
}
