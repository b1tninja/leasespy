# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9915 | Internet Standard (STD 102) | 2026-01 | 2026-11-05 |
| RFC 2131 | Draft Standard | 1997-03 | 2026-11-05 |
| RFC 2132 | Draft Standard | 1997-03 | 2026-11-05 |
| RFC 3046 | Proposed Standard | 2001-01 | 2026-11-05 |
| RFC 6422 | Proposed Standard | 2011-12 | 2026-11-05 |
| RFC 5007 | Proposed Standard | 2007-09 | 2026-11-05 |
| RFC 7653 | Proposed Standard | 2015-10 | 2026-11-05 |
| RFC 8156 | Proposed Standard | 2017-06 | 2026-11-05 |
| RFC 3396 | Proposed Standard, updates RFC 2131 (DHCPv4 long options) | 2002-11 | 2026-11-13 |
| RFC 4361 | Proposed Standard, updates RFC 2131, 2132 and 3315, updated by RFC 5494 (node-specific client identifiers) | 2006-02 | 2026-11-13 |
| RFC 6842 | Proposed Standard, updates RFC 2131 (client identifier in server replies) | 2013-01 | 2026-11-13 |
| RFC 4388 | Proposed Standard, updated by RFC 6148 (DHCPv4 leasequery) | 2006-02 | 2026-11-13 |
| RFC 6148 | Proposed Standard, updates RFC 4388 (DHCPv4 leasequery by relay agent Remote ID) | 2011-02 | 2026-11-13 |
| RFC 5460 | Proposed Standard, updated by RFC 7653 (DHCPv6 bulk leasequery) | 2009-02 | 2026-11-13 |
| RFC 5494 | Proposed Standard, IANA allocation guidelines for ARP (hardware types) | 2009-04 | 2026-11-13 |
| RFC 6607 | Proposed Standard, updates RFC 3046 (virtual subnet selection, sub-option copying) | 2012-04 | 2026-11-13 |
| RFC 6939 | Proposed Standard (client link-layer address option in DHCPv6) | 2013-05 | 2026-11-13 |
| RFC 6221 | Proposed Standard, updates RFC 3315 (lightweight DHCPv6 relay agent) | 2011-05 | 2026-11-13 |
| RFC 7227 | BCP 187, updates RFC 3315 (guidelines for new DHCPv6 options) | 2014-05 | 2026-11-13 |
| RFC 7844 | Proposed Standard (anonymity profiles; cited by RFC 9915 sec. 11) | 2016-05 | 2026-11-13 |
| RFC 6355 | Proposed Standard (DUID-UUID) | 2011-08 | 2026-11-13 |
| RFC 8415 | OBSOLETE, obsoleted by RFC 9915 | 2018-11 | 2026-11-13 |
| RFC 3315 | OBSOLETE, obsoleted by RFC 8415, which RFC 9915 obsoletes in turn | 2003-07 | 2026-11-13 |

RFC 8415 and RFC 3315 are listed so an agent that finds them cited knows they are superseded;
cite RFC 9915. RFC 6422, RFC 6221 and RFC 7227 say they update RFC 3315: read that as RFC 9915.
RFC 8156 is written in RFC 3315 and RFC 8415 vocabulary (it predates the removal of IA_TA and server
unicast); reading it against RFC 9915 needs a note per use.

Per-document facts recorded on 2026-11-13 with rfclib (`info`, `errata`, `read`):

| Document | Errata | What the code depends on |
|---|---|---|
| RFC 9915 | 1 verified: 8821, Editorial, sec. 18.2.7 (text says Renew where Release is meant) | sec. 7.3, 7.6, 7.7, 8, 9, 11, 15, 16, 21.1, 21.4, 21.19 read in full for the first codec pass |
| RFC 5007 | 2 verified: 3763 (Technical, sec. 4.3.3 and 4.3.4), 4816 (Editorial) | erratum 3763 is an erratum id, not an RFC number; see the errata watch in ROADMAP.md |
| RFC 4361 | 1 verified (3954, Editorial, sec. 7: expansion of MAC), 3 held for document update | not yet read for implementation |
| RFC 4388 | 1 verified (3518, Technical, sec. 6.4.1: ciaddr in DHCPLEASEACTIVE/DHCPLEASEUNASSIGNED), 2 held, 1 rejected | not yet read for implementation |
| RFC 5460 | 1 verified (3571, Technical, sec. 5.2.1: Client-ID in LEASEQUERY-DATA is the requestor's) | not yet read for implementation |
| RFC 3396, 6842, 6148, 6607, 6939, 7653, 7844, 6355 | none | not yet read for implementation |
| RFC 6221 | 0 verified, 1 on file | not yet read for implementation |

Facts that are not in any RFC: the numeric option codes of the obsolete IA_TA and Server Unicast
options (RFC 9915 sec. 21.5 and sec. 21.12 point back to RFC 8415 without restating them), the
status code values, and the names and numbers of every option beyond those RFC 9915 sec. 21 states.
Their body is the IANA DHCPv6 parameters registry, which is not vendored: see the
`registry.iana-snapshot` row in ROADMAP.md. Until a dated snapshot exists, nothing here uses those
numbers; `leasespy.options` defines only codes stated in an RFC 9915 section.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
