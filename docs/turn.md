# Relay protocols

## TURN

- standard
- supported in browsers, with DataChannel.
- multiple implementations
- supports auth

## IPFS relay

- more complicated, higher overhead, over multiple transports

## H2 relay

- a variant of IPFS relay, using H2/H3 transports.
- Istio gateway like, but with BTS and reverse

## SNI relay

Used in current istio without BTS - not practical - lacks auth, one way.

Useful to support HTTPS servers, relay to other servers without termination.
