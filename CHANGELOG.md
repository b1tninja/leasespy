# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- DHCPv4: the message codec (`wire.decode_v4`, `encode_v4`, `leasespy.wire4`), option framing with
  RFC 3396 aggregation and splitting, option overload on decode, the RFC 4361 client identifier
  (`leasespy.options4`), a generated IANA option and message-type table with provenance
  (`leasespy._iana_dhcp`, `tools/gen_iana_dhcp.py`), and a sans-IO client state machine
  (`leasespy.client4`). Coverage floor raised to 90.
- DHCPv6 first pass: option framing and IA_NA (`options`), client/server and relay message headers
  with bounded relay unwrapping (`wire`), the opaque `Duid` value type with a diagnostic view
  (`duid`), the RFC 9915 sec. 16 validation table (`validate`) and the sec. 15 retransmission
  schedule (`fsm`). `DhcpError` is the one exception decoders raise.
- Citation fixes: RFC 5494 is not about the client identifier in server replies (RFC 6842 is), and
  "3763" is an erratum id on RFC 5007. The DUID row now follows RFC 9915 sec. 11 (opaque).
- Everything else, including DHCPv4, remains a stub that raises `NotImplementedError`;
  [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for leasespy.
- `leasespy.apps` namespace reserved for composition that is not protocol behaviour.
