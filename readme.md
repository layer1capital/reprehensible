## Comparison to QUIC

Reprehensible:
- does not use TLS or PKI
- does not implement multiplexing
- does not assume udp as the underlying transport

Reprehensible listeners do not preform any handshake. Connections are semantically stateless like udp.

## Why the name?

The name "reprehensible" was randomly selected.

## Gotchas

Reprehensible does not provide forward secrecy.

Reprehensible does not protect against replay attacks.

## Philosophy

- Reprehensible is small, simple, narrow in scope.
- Aside from the stated goals, reprehnsible does not implement any feature, e.g. multiplexing, that can be implemented
  in a separate network layer.
- Example implementations should be provided for ommitted features.

## Goals

- Provide end-to-end, authenticated encryption for unordered datagrams.
