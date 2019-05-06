## Comparison to QUIC

Reprehensible does not use PKI like TLS.
Reprehensible does not implement multiplexing.
Reprehensible does not assume udp as the underlying transport.
Reprehensible does not specify any handshake. Connections are semantically stateless like udp.

## Comparison to DTLS

TODO

## Why the name?

The name "reprehensible" was randomly selected.

## Gotchas

Reprehensible does not provide forward secrecy.

Reprehensible does not protect against replay attacks.

Reprehensible does not deal with ip fragmentation.

## Philosophy

- Reprehensible is small, simple, and arrow in scope.
- Aside from the stated goals, reprehnsible does not implement any feature, e.g. multiplexing, that can be implemented
  in a separate network layer.
- Example implementations should be provided for ommitted features.

## Goals

- Provide end-to-end, authenticated encryption for unordered datagrams.
