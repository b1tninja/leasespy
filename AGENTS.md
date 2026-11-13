# Instructions for coding agents

DHCPv4 and DHCPv6 on asyncio: sans-IO state machines, the option registry, relay agents with option 82, leasequery and the failover peer protocol.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` records what is owed, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project leasespy

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy leasespy tests

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[ok]` unless
   the test named in its `Where` cell exists, passes, and would fail if the behaviour
   regressed. A Where cell marked `(to be written)` names a test nobody has written:
   write it, then drop the marker in the same commit that flips the row.
   `tests/test_roadmap_rows.py` checks only that every row names a callable the
   package defines; it cannot tell a passing test from a missing one, so this rule
   is the check. Do not weaken that test, skip it, or delete it to get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with `rfclib` and
   cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** `pyproject.toml` here declares no runtime dependencies. Adding a runtime
   dependency needs a paragraph of justification in `docs/strategy.md` explaining
   why the standard library is not enough.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 2131 carries 7 verified errata, all Editorial (typos and alignment), so none changes packet handling. It is updated by RFC 3396 (long options), RFC 4361 (node-specific client identifiers), RFC 5494 and RFC 6842 (client identifier in server replies): the codec is written against those updates, not the 1997 text alone.
- RFC 2132 carries 2 verified errata and 5 updates.
- RFC 5007 carries 2 verified errata. 3763 (Technical) rewrites sec. 4.3.3 and sec. 4.3.4: a LEASEQUERY-REPLY whose OPTION_CLIENT_DATA has no OPTION_CLT_TIME is no longer discarded, and when sources conflict the reply carrying OPTION_CLT_TIME is preferred. Leasequery against a failover pair depends on it.
- RFC 9915 carries 1 verified erratum and removes IA_TA plus server unicast: implementing RFC 8415 today builds the obsolete behaviour in.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfclib` calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
