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
| `wire.decode_v4()` | RFC 2131 sec. 2 (Figure 1, Table 1), RFC 2132 sec. 9.3, RFC 3396 sec. 5 to sec. 7: the 236-octet header, the magic cookie, options aggregated, option overload read file then sname after the options field, a message without the cookie returned as BOOTP with its vendor field raw, `op` other than 1 or 2 and `hlen` above 16 refused. Raises `DhcpError` only | `[ok]` | `tests/test_wire_v4.py::test_decode_v4`, `tests/test_wire_v4.py::test_option_overload_reads_file_then_sname_in_rfc3396_order`, `tests/test_wire_v4.py::test_missing_cookie_is_bootp_with_raw_vendor_field`, `tests/test_wire_v4.py::test_malformed_headers_raise_dhcperror`, `tests/test_wire_v4.py::test_fuzz_seeded_never_other_exception` | M1 |
| `wire.encode-v4` | RFC 2131 sec. 2, RFC 3396 sec. 6: every option goes in the options field, split at 255 octets; sname and file are strings of at most 63 and 127 octets plus the NUL | `[ok]` | `tests/test_wire_v4.py::test_encode_v4`, `tests/test_wire_v4.py::test_long_option_survives_a_message_round_trip`, `tests/test_wire_v4.py::test_encode_refuses_a_bad_op_and_a_short_address` | M1 |
| `wire.encode-v4-overload` | RFC 2132 sec. 9.3, RFC 3396 sec. 4 paragraph 1 (a long option MUST be split, and may use the other buffers): moving options into file and sname when the options field is full. `encode_message4(message, options_limit=N)` packs first fit, spills into `file` then `sname`, adds option 52, ends each buffer with End, splits an option across buffers only when it fits none whole, and refuses what cannot fit. **The limit is the caller's:** RFC 2132 sec. 9.10 does not say whether the 28 octets of IP and UDP header count toward the "maximum length DHCP message", so deriving N from option 57 is not done here | `[ok]` | `tests/test_wire_v4.py::test_encode_overloads_file_and_sname_when_the_options_field_is_full`, `tests/test_wire_v4.py::test_overload_uses_sname_after_file_and_says_so_with_value_3`, `tests/test_wire_v4.py::test_a_string_in_file_keeps_file_out_of_the_options`, `tests/test_wire_v4.py::test_an_option_that_fits_no_field_whole_is_split_with_the_same_code_in_order`, `tests/test_wire_v4.py::test_overload_refuses_what_cannot_fit_and_option_52_supplied_by_the_caller` | M1 |
| `options.encode_option()` | RFC 9915 sec. 21.1 (DHCPv6 only); the DHCPv4 framing is `options4.encode_options4` (`options.long-options-v4`) | `[part]` | `tests/test_options_v6.py::test_single_option_bytes` | M1 |
| `options.decode_options()` | RFC 9915 sec. 21.1, sec. 16 (unknown options kept) | `[ok]` | `tests/test_options_v6.py::test_decode_options_roundtrip`, `tests/test_options_v6.py::test_unknown_option_code_kept_not_dropped` | M1 |
| `options.decode_ia_na()` | RFC 9915 sec. 21.4 | `[ok]` | `tests/test_options_v6.py::test_ia_na_option_len_is_12_plus_suboptions` | M1 |
| `options.encode_ia_na()` | RFC 9915 sec. 21.4 | `[ok]` | `tests/test_options_v6.py::test_ia_na_decode_fields` | M1 |
| `options.hostile-input-bounds` | decoders raise only `DhcpError`, never read past the buffer, bound relay nesting | `[part]` | `tests/test_options_v6.py::test_fuzz_seeded_never_other_exception`, `tests/test_wire_v6.py::test_fuzz_seeded_never_other_exception` | M1 |
| `options.v4-registry` | RFC 2132 and the IANA bootp-dhcp-parameters registry: framing (Pad 0 and End 255 only have no length, sec. 2 paragraph 1), unknown codes kept, and IANA's names for every code through `option_name` over a generated, hashed table (`registry.iana-dhcpv4`). `options4_typed.decode_typed` reads the 73 RFC 2132 options with a defined layout (addresses and lists, pairs, time offset, 8-, 16- and 32-bit values, switches, NVT ASCII text, the plateau table, node type, message type, overload, parameter request list, opaque vendor data) and refuses a wrong length, a switch above 1, a value under the section's minimum, an unordered plateau table, a default-route static route (sec. 5.8 paragraph 3) and a non-ASCII text octet. A code it does not know returns None, so the option stays an opaque `Option4`. **Findings:** RFC 2132 erratum 486 (the message type figure says 1-9, the list 1-8) is moot because later RFCs add types, so any nonzero octet is read; IANA's length column says "N" for option 16 where RFC 2132 sec. 3.18 says 4 (the RFC wins; recorded in the test). Options outside RFC 2132 are `options.v4-typed-extensions` | `[ok]` | `tests/test_options_v4.py::test_decode_v4_options`, `tests/test_options_v4.py::test_pad_and_end_have_no_length_octet`, `tests/test_options_v4.py::test_truncated_option_raises_dhcperror`, `tests/test_iana_dhcp.py::test_the_codes_the_codec_names_carry_iana_s_names`, `tests/test_options_v4_typed.py::test_every_decoded_fixed_length_agrees_with_the_length_iana_writes`, `tests/test_options_v4_typed.py::test_address_lists_need_a_multiple_of_four_and_at_least_one`, `tests/test_options_v4_typed.py::test_a_static_route_to_the_default_destination_is_illegal` | M1 |
| `options.v4-typed-extensions` | Typed decoders for the DHCPv4 options defined after RFC 2132: relay agent information (82, RFC 3046, RFC 6607), client FQDN (81, RFC 4702), classless static routes (121, RFC 3442), domain search (119, RFC 3397), and the rest of IANA's 169 rows. Each needs its own RFC read through rfclib and its errata | `[ ]` | `tests/test_options_v4_typed.py::test_option_121_classless_routes` (to be written) | M4 |
| `options.long-options-v4` | RFC 3396 (no errata): repeated codes concatenate in aggregate-buffer order on decode (sec. 7), encode splits at 255 octets in order (sec. 6), the RFC's own sec. 8 example (option 67, 7 + 6 octets) is the vector. A duplicated option 53 becomes two octets and is refused, the reading sec. 7 paragraph 1 forces | `[ok]` | `tests/test_options_v4.py::test_rfc3396_section_8_example_concatenates`, `tests/test_options_v4.py::test_concatenates_repeated_options`, `tests/test_options_v4.py::test_long_option_is_split_at_255_and_round_trips`, `tests/test_wire_v4.py::test_duplicate_message_type_makes_a_two_octet_option_and_is_refused` | M1 |
| `options.client-id-v4` | RFC 4361 sec. 6.1 paragraph 3 (type 255, 4-octet IAID, DUID), RFC 2132 sec. 9.14 as amended by RFC 4361 sec. 6.5 (the minimum length of 2 is deleted), RFC 6842 sec. 3 (a server echoes the identifier unaltered; a client discards a reply whose identifier differs, which `Client4` does). **Findings:** RFC 4361 refers to RFC 3315 for the IAID and DUID, and RFC 3315 is obsolete (RFC 8415, then RFC 9915); its sec. 3, 5 and 6 cite 6.3 and 6.4 where 6.4 and 6.5 are meant (held errata 5424 to 5426); RFC 5494 is about ARP hardware types, not the client identifier | `[ok]` | `tests/test_options_v4.py::test_node_specific_client_id`, `tests/test_options_v4.py::test_legacy_client_id_is_type_then_hardware_address`, `tests/test_options_v4.py::test_short_client_ids_are_refused`, `tests/test_client4.py::test_a_server_reply_with_a_different_client_identifier_is_discarded` | M1 |
| `registry.iana-dhcpv4` | IANA bootp-dhcp-parameters (CC0 1.0), read 2026-11-13 from `iana.org/assignments/bootp-dhcp-parameters/` (registry updated 2026-02-02, `Last-Modified` 2026-10-13): `leasespy/_iana_dhcp.py` is generated by `tools/gen_iana_dhcp.py`, records the file's sha256 and size and the licence, holds 169 option-code rows, 21 range rows and the 18 message types, and cites rows as `iana:bootp-dhcp-parameters§options#53`. **Findings:** IANA's names are not the RFC titles (code 53 is "DHCP Msg Type", 61 "Client Id", 52 "Overload"); the registry lists message types 9 to 18 that RFC 2132 does not (RFC 2132 verified erratum 486 limits its own table to 1 to 8); IANA gives code 16 length N where RFC 2132 says 4 (held erratum 487) | `[ok]` | `tests/test_iana_dhcp.py::test_snapshot_is_dated_and_hashed`, `tests/test_iana_dhcp.py::test_the_client_message_types_match_the_registry`, `tests/test_iana_dhcp.py::test_ranges_and_unknowns_are_named_not_invented` | M1 |
| `fsm.client4` | RFC 2131 sec. 3.1, sec. 4.1 paragraph 8, sec. 4.4.1, sec. 4.4.5, RFC 6842 sec. 3: sans-IO `Client4` on a virtual clock with an injected RNG. INIT, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING; OFFER selection by xid; REQUEST with xid, server id and requested address; lease counted from the REQUEST; T1 and T2 from options 58 and 59 or 0.5 and 0.875, falling back when they break T1 < T2 < expiry; unicast renew, broadcast rebind; retry at half the remaining time, 60 seconds minimum; expiry and NAK back to INIT; 4, 8, 16, 32, 64 second backoff with plus or minus 1 second. Missing: INIT-REBOOT, DHCPINFORM, DECLINE after an address probe, RELEASE, selecting among several offers | `[part]` | `tests/test_client4.py::test_an_ack_binds_with_default_t1_t2_counted_from_the_request`, `tests/test_client4.py::test_t1_renews_by_unicast_with_ciaddr_and_no_server_id_or_requested_address`, `tests/test_client4.py::test_t2_rebinds_by_broadcast`, `tests/test_client4.py::test_renewing_retries_after_half_the_time_to_t2_never_under_sixty_seconds`, `tests/test_client4.py::test_lease_expiry_drops_the_address_and_returns_to_init`, `tests/test_client4.py::test_discover_retransmits_after_4_8_16_32_then_64_seconds` | M2 |
| `fsm.client4-init-reboot` | RFC 2131 sec. 4.4.2 (INIT-REBOOT and REBOOTING: a REQUEST with the requested address and no server identifier). `Client4.start_reboot` broadcasts it with `ciaddr` zero (also sec. 3.2 paragraph 2), keeps its `xid` and the sec. 4.1 schedule, binds on an ACK from any server counting the lease from the REQUEST, and restarts discovery on a NAK (sec. 3.2 paragraph 10). Not done: sec. 3.2 paragraph 11's MAY of using the old address when nothing answers after about 60 seconds, which is the caller's policy | `[ok]` | `tests/test_client4_paths.py::test_init_reboot_requests_the_remembered_address`, `tests/test_client4_paths.py::test_an_ack_from_any_server_binds_and_the_lease_counts_from_the_request`, `tests/test_client4_paths.py::test_a_nak_in_init_reboot_restarts_with_a_discover`, `tests/test_client4_paths.py::test_init_reboot_retransmits_the_same_request_on_the_4_8_16_schedule` | M2 |
| `fsm.client4-inform-decline-release` | RFC 2131 sec. 4.4.3 (DHCPINFORM, 60 seconds or 4 tries), sec. 4.4.1 paragraph 8 (DECLINE when an ARP probe finds the address in use), sec. 4.4.6 (RELEASE). `Inform4` is a separate machine (no lease): `ciaddr` set, none of requested IP, lease time or server identifier (Table 5), unicast to a known server else broadcast, an ACK with its `xid` finishes it, `GaveUp` after 4 tries or 60 seconds. `Client4.address_in_use` sends the broadcast DECLINE of Table 5 (requested IP and server identifier, no parameter list, flags and `ciaddr` zero) and records the ten-second wait of sec. 3.1 paragraph 18 as `restart_not_before`; `Client4.release` unicasts the RELEASE (`ciaddr`, server identifier, no requested IP). Not done: the ARP probe itself, which is the caller's (sec. 4.4.1 paragraph 8) | `[ok]` | `tests/test_client4_paths.py::test_decline_after_an_address_conflict`, `tests/test_client4_paths.py::test_release_is_unicast_with_ciaddr_and_the_server_and_no_requested_address`, `tests/test_client4_paths.py::test_inform_has_ciaddr_and_none_of_the_forbidden_options`, `tests/test_client4_paths.py::test_inform_retransmits_with_the_same_xid_and_gives_up_after_four_tries`, `tests/test_client4_paths.py::test_an_ack_with_the_same_xid_finishes_the_inform` | M2 |
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
| `docs.spine-unread` | RFC 4388, 6148, 5460, 7653, 6607, 6939, 6221, 7227, 7844, 6355 are in docs/rfc-map.md with status and errata but not yet read for implementation | `[ ]` | `tests/test_roadmap_rows.py::test_spine_read_for_every_cited_rfc` (to be written) | - |

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
