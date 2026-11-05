# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation leasespy could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `wire.decode_v6()` | RFC 9915 sec. 8 | `[ ]` | `tests/test_obligations.py::decode_v6` |
| `wire.encode_v6()` | RFC 9915 sec. 8 | `[ ]` | `tests/test_obligations.py::encode_v6` |
| `wire.decode_v4()` | RFC 2131 | `[ ]` | `tests/test_obligations.py::decode_v4` |
| `options.encode_option()` | RFC 2132, RFC 9915 sec. 21 | `[ ]` | `tests/test_obligations.py::encode_option` |
| `options.decode_options()` | RFC 9915 sec. 21 | `[ ]` | `tests/test_obligations.py::decode_options` |
| `duid.parse_duid()` | RFC 9915 sec. 11 | `[ ]` | `tests/test_obligations.py::parse_duid` |
| `fsm.client_step()` | RFC 9915 sec. 18 | `[ ]` | `tests/test_obligations.py::client_step` |
| `validate.check_message()` | RFC 9915 sec. 16 | `[ ]` | `tests/test_obligations.py::check_message` |
| `relay.wrap_relay_forward()` | RFC 9915 sec. 9 | `[ ]` | `tests/test_obligations.py::wrap_relay_forward` |
| `leasequery.build_query()` | RFC 5007 | `[ ]` | `tests/test_obligations.py::build_query` |
| `failover.peer_transition()` | RFC 8156 | `[ ]` | `tests/test_obligations.py::peer_transition` |

## 2. Milestones

- M1 wire codec and option registry for both families, with RFC 2131 errata applied
- M2 sans-IO client state machines on a virtual clock, including RFC 9915 retransmission
- M3 server allocation for addresses and prefixes, DUID stability included
- M4 relay with option 82 and RFC 6422, verified against a real relay
- M5 leasequery and active leasequery
- M6 failover peer protocol, then publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 2131 carries 7 verified errata and is updated by RFC 3396, RFC 4361, RFC 5494 and RFC 6842. The errata change packet handling, so the codec is written against them, not the 1997 text alone.
- RFC 2132 carries 2 verified errata and 5 updates.
- RFC 9915 carries 1 verified erratum and removes IA_TA plus server unicast: implementing RFC 8415 today builds the obsolete behaviour in.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a packet crafting tool: use scapy for that and this library will not pretend otherwise | `[no]` | a named document requires it |
| a complete production server: leases persist behind an interface, storage is the operator's choice | `[no]` | a named document requires it |
| PXE, PXP or DOCSIS suboptions in the first release, only the registry hooks for them | `[no]` | a named document requires it |

## 5. Open questions

- which lease store interface keeps a production server possible without embedding one
- how far to chase RFC 9915 conformance while peers still speak RFC 8415 behaviour

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
