# leasespy

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

leasespy -- DHCP clients, servers and relays on asyncio

DHCPv6 was reissued in January 2026 as RFC 9915, an Internet Standard (STD 102) that obsoletes RFC 8415 and deliberately removes IA_TA and the server unicast option. No implementation in any language has finished that transition, and no Python library is written against it. The Python field is contested but shallow: pydhcp 0.9.1 (2026-10-21) is young and IPv4-first, dhcpkit 1.0.7 has not moved since 2017, pydhcplib stopped in 2014, and dhcpy 0.0.7 drives the Kea control API rather than the protocol. leasespy takes the ground nobody holds: the relay and failover half of DHCP, where an operator's problem actually lives.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| pydhcp | 0.9.1 | 2026-10-21 | active and IPv4-centred; no relay, leasequery or failover |
| dhcpy | 0.0.7 | 2024-10-09 | an ISC Kea control API client, not the DHCP protocol |
| dhcpkit | 1.0.7 | 2017-06-25 | IPv6 only, unmaintained for nine years |
| scapy | 2.8.0 | 2026-10-02 | packet forgery; no allocation state machine or lease store |

What this project intends to add:

- DHCPv6 written to RFC 9915 from the first commit, with IA_TA and server unicast absent by construction
- a sans-IO state machine per RFC 2131 and RFC 9915 sec. 14 through sec. 18, testable on a virtual clock
- relay agent with option 82 and RFC 6422 relay-supplied options, which is where real deployments break
- leasequery and active leasequery so a monitoring system can read a live server
- failover peer state machine, which no Python library attempts at all

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9915 | Internet Standard (STD 102) | 2026-01 | current DHCPv6: message formats, DUID, IA, relay, options |
| RFC 2131 | Draft Standard | 1997-03 | DHCPv4 client and server state machines |
| RFC 2132 | Draft Standard | 1997-03 | the DHCP option and BOOTP vendor extension registry |
| RFC 3046 | Proposed Standard | 2001-01 | relay agent information, option 82 |
| RFC 6422 | Proposed Standard | 2011-12 | relay-supplied options for DHCPv6 |
| RFC 5007 | Proposed Standard | 2007-09 | DHCPv6 leasequery |
| RFC 7653 | Proposed Standard | 2015-10 | DHCPv6 active leasequery |
| RFC 8156 | Proposed Standard | 2017-06 | DHCPv6 failover between cooperating servers |

### Errata watch

- RFC 2131 carries 7 verified errata, all Editorial (typos and alignment), so none changes packet handling. It is updated by RFC 3396 (long options), RFC 4361 (node-specific client identifiers), RFC 5494 and RFC 6842 (client identifier in server replies): the codec is written against those updates, not the 1997 text alone.
- RFC 2132 carries 2 verified errata and 5 updates.
- RFC 5007 carries 2 verified errata. 3763 (Technical) rewrites sec. 4.3.3 and sec. 4.3.4: a LEASEQUERY-REPLY whose OPTION_CLIENT_DATA has no OPTION_CLT_TIME is no longer discarded, and when sources conflict the reply carrying OPTION_CLT_TIME is preferred. Leasequery against a failover pair depends on it.
- RFC 9915 carries 1 verified erratum and removes IA_TA plus server unicast: implementing RFC 8415 today builds the obsolete behaviour in.

## Module layout

| Module | Responsibility |
|---|---|
| `wire` | DHCPv4 and DHCPv6 message formats (RFC 2131, RFC 9915 sec. 8, sec. 9) |
| `options` | option registry, encoders and decoders (RFC 2132, RFC 9915 sec. 21) |
| `duid` | DUID types and stability rules (RFC 9915 sec. 11) |
| `identity` | identity associations: address and prefix binding (RFC 9915 sec. 12) |
| `fsm` | client and server state machines with retransmission (RFC 9915 sec. 14, sec. 15, sec. 18) |
| `validate` | message validation and error handling (RFC 9915 sec. 16) |
| `relay` | relay forwarding and option 82 (RFC 9915 sec. 19, RFC 3046, RFC 6422) |
| `leasequery` | query and active query (RFC 5007, RFC 7653) |
| `failover` | peer protocol and states (RFC 8156) |
| `clock` | sans-IO timers so every timeout is testable without sleeping |

## What it does not do

- a packet crafting tool: use scapy for that and this library will not pretend otherwise
- a complete production server: leases persist behind an interface, storage is the operator's choice
- PXE, PXP or DOCSIS suboptions in the first release, only the registry hooks for them


## Install

```bash
git clone https://github.com/b1tninja/leasespy.git
cd leasespy
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy leasespy tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
