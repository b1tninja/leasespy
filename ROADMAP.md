# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation leasespy could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `wire.decode_v6()` | RFC 9915 sec. 7.3, sec. 8, sec. 9 | `[ok]` | `tests/test_wire_v6.py::test_client_server_header`, `tests/test_wire_v6.py::test_unknown_msg_type_returned_not_raised` | M1 |
| `wire.encode_v6()` | RFC 9915 sec. 8, sec. 9 | `[ok]` | `tests/test_wire_v6.py::test_roundtrip_each_of_the_eleven_client_server_types`, `tests/test_wire_v6.py::test_relay_forward_header_is_34_octets` | M1 |
| `wire.unwrap_relays()` | RFC 9915 sec. 9 | `[ok]` | `tests/test_wire_v6.py::test_nested_depth_bound_raises_dhcperror_not_recursionerror` | M1 |
| `wire.decode_v4()` | RFC 2131, RFC 3396 | `[ ]` | `tests/test_wire_v4.py::test_decode_v4` (to be written) | M1 |
| `wire.encode-v4` | RFC 2131 | `[ ]` | `tests/test_wire_v4.py::test_encode_v4` (to be written) | M1 |
| `options.encode_option()` | RFC 9915 sec. 21.1 (DHCPv6 only); RFC 2132 not started | `[part]` | `tests/test_options_v6.py::test_single_option_bytes` | M1 |
| `options.decode_options()` | RFC 9915 sec. 21.1, sec. 16 (unknown options kept) | `[ok]` | `tests/test_options_v6.py::test_decode_options_roundtrip`, `tests/test_options_v6.py::test_unknown_option_code_kept_not_dropped` | M1 |
| `options.decode_ia_na()` | RFC 9915 sec. 21.4 | `[ok]` | `tests/test_options_v6.py::test_ia_na_option_len_is_12_plus_suboptions` | M1 |
| `options.encode_ia_na()` | RFC 9915 sec. 21.4 | `[ok]` | `tests/test_options_v6.py::test_ia_na_decode_fields` | M1 |
| `options.hostile-input-bounds` | decoders raise only `DhcpError`, never read past the buffer, bound relay nesting | `[part]` | `tests/test_options_v6.py::test_fuzz_seeded_never_other_exception`, `tests/test_wire_v6.py::test_fuzz_seeded_never_other_exception` | M1 |
| `options.v4-registry` | RFC 2132 | `[ ]` | `tests/test_options_v4.py::test_decode_v4_options` (to be written) | M1 |
| `options.long-options-v4` | RFC 3396 | `[ ]` | `tests/test_options_v4.py::test_concatenates_repeated_options` (to be written) | M1 |
| `options.client-id-v4` | RFC 4361, RFC 6842, RFC 5494 | `[ ]` | `tests/test_options_v4.py::test_node_specific_client_id` (to be written) | M1 |
| `duid.parse_duid()` | RFC 9915 sec. 11: an opaque value, compared only for equality, with an optional diagnostic view of types 1 to 4 | `[ok]` | `tests/test_duid.py::test_parse_duid_en_example`, `tests/test_duid.py::test_unknown_type_accepted_and_describe_is_none` | M1 |
| `duid.generation` | RFC 9915 sec. 11.2 to sec. 11.5 (needs stable storage), RFC 6355 | `[ ]` | `tests/test_duid_generate.py::test_generated_duid_is_stable` (to be written) | M3 |
| `fsm.retransmission_schedule()` | RFC 9915 sec. 15, sec. 7.6 Table 1 | `[ok]` | `tests/test_retransmit.py::test_request_schedule_rand_zero`, `tests/test_retransmit.py::test_cap_applies_mrt_plus_rand_mrt` | M2 |
| `fsm.solicit-retransmission` | RFC 9915 sec. 18.2.1 (first RT strictly greater than IRT, Advertise collection) | `[ ]` | `tests/test_retransmit.py::test_solicit_first_rt_exceeds_irt` (to be written) | M2 |
| `fsm.client_step()` | RFC 9915 sec. 18 (the state transition table; retransmission is the row above) | `[ ]` | `tests/test_fsm_client.py::test_client_step` (to be written) | M2 |
| `fsm.server-step` | RFC 9915 sec. 18.3 | `[ ]` | `tests/test_fsm_server.py::test_server_step` (to be written) | M3 |
| `validate.check_message()` | RFC 9915 sec. 16 and sec. 16.2 to sec. 16.14, per message type and role | `[ok]` | `tests/test_validate_v6.py::test_server_discards_request_without_server_id`, `tests/test_validate_v6.py::test_every_message_type_times_every_role_has_a_verdict` | M1 |
| `validate.rkap-verification` | RFC 9915 sec. 20.4 (check_message only tests that Reconfigure carries an Authentication option) | `[ ]` | `tests/test_auth.py::test_reconfigure_key_verified` (to be written) | M2 |
| `relay.wrap_relay_forward()` | RFC 9915 sec. 19.1 to sec. 19.4 (behaviour), sec. 9.1 (format), sec. 7.6 HOP_COUNT_LIMIT | `[ ]` | `tests/test_relay.py::test_wrap_relay_forward` (to be written) | M4 |
| `relay.option82-v4` | RFC 3046, RFC 6607 (sub-option copying, virtual subnet selection) | `[ ]` | `tests/test_relay_v4.py::test_option82_roundtrip` (to be written) | M4 |
| `leasequery.build_query()` | RFC 5007, with erratum 3763 (CLT_TIME) and erratum 4816 (option 48 is OPTION_LQ_CLIENT_LINK) | `[ ]` | `tests/test_leasequery.py::test_build_query` (to be written) | M5 |
| `leasequery.v4-query` | RFC 4388, RFC 6148, with erratum 3518 | `[ ]` | `tests/test_leasequery_v4.py::test_dhcpleasequery` (to be written) | M5 |
| `leasequery.bulk-v6` | RFC 5460 with erratum 3571 | `[ ]` | `tests/test_leasequery_bulk.py::test_bulk_query` (to be written) | M5 |
| `leasequery.active-v6` | RFC 7653 (updates RFC 5460) | `[ ]` | `tests/test_leasequery_active.py::test_active_query` (to be written) | M5 |
| `failover.peer_transition()` | RFC 8156 (written in RFC 3315 vocabulary; read against RFC 9915) | `[ ]` | `tests/test_failover.py::test_peer_transition` (to be written) | M6 |
| `registry.iana-snapshot` | IANA DHCPv6 parameters registry (not an RFC): option codes for the obsolete IA_TA and Server Unicast, status codes, option names; blocked on a primarysource `iana` collection, being researched | `[ ]` | `tests/test_registry.py::test_snapshot_is_dated_and_hashed` (to be written) | - |
| `docs.spine-unread` | RFC 3396, 4361, 6842, 4388, 6148, 5460, 7653, 6607, 6939, 6221, 7227, 7844, 6355 are in docs/rfc-map.md with status and errata but not yet read for implementation | `[ ]` | `tests/test_roadmap_rows.py::test_spine_read_for_every_cited_rfc` (to be written) | - |

## 2. Milestones

- M1 wire codec and option registry for both families, with the RFC 2131 updates applied, and the DUID value type, which validation and the client both need (moved up from M3 on 2026-11-13)
- M2 sans-IO client state machines on a virtual clock, including RFC 9915 retransmission
- M3 server allocation for addresses and prefixes, DUID stability included
- M4 relay with option 82 and RFC 6422, verified against a real relay
- M5 leasequery and active leasequery
- M6 failover peer protocol, then publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 2131 carries 7 verified errata, all Editorial (typos and alignment), so none changes packet handling. It is updated by RFC 3396 (long options), RFC 4361 (node-specific client identifiers), RFC 5494 (IANA allocation guidelines for ARP, which govern the hardware-type values in `htype`, DUID-LLT and DUID-LL) and RFC 6842 (client identifier in server replies): the codec is written against those updates, not the 1997 text alone. Correction, 2026-11-13: this line used to credit RFC 5494 with the client identifier in server replies. Only RFC 6842 is about that.
- RFC 2132 carries 2 verified errata and 5 updates.
- RFC 5007 carries 2 verified errata. Erratum 3763 (Technical; an erratum id on RFC 5007, not an RFC number) rewrites sec. 4.3.3 and sec. 4.3.4: a LEASEQUERY-REPLY whose OPTION_CLIENT_DATA has no OPTION_CLT_TIME is no longer discarded, and when sources conflict the reply carrying OPTION_CLT_TIME is preferred. Leasequery against a failover pair depends on it. Erratum 4816 (Editorial): the text says OPTION_CLIENT_LINK where the registry name is OPTION_LQ_CLIENT_LINK (option 48), so a decoder takes the registry name.
- RFC 9915 carries 1 verified erratum (8821, Editorial, sec. 18.2.7: the text says Renew where Release is meant) and removes IA_TA plus server unicast: implementing RFC 8415 today builds the obsolete behaviour in.

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
