"""A sans-IO DHCPv4 client state machine on a virtual clock (RFC 2131 section 3.1, 4.4).

No sockets and no clock: every call takes the time as an argument and returns the actions the
caller must perform (send this message, configure this address, drop it). Randomness is an
injected object with ``uniform`` and ``randint`` (a seeded :class:`random.Random` in tests), so a
whole exchange is reproducible.

States implemented: INIT, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING (RFC 2131 Figure 5),
and REBOOTING, reached by :meth:`Client4.start_reboot` (section 4.4.2, INIT-REBOOT). DHCPINFORM
(section 4.4.3) is the separate :class:`Inform4`, because it has no lease. DHCPDECLINE and
DHCPRELEASE are :meth:`Client4.address_in_use` and :meth:`Client4.release`.

Rules, each pinned in ``tests/test_client4.py``:

* section 4.4.1 paragraph 3: an OFFER whose ``xid`` is not the DISCOVER's is discarded, and any
  ACK in SELECTING is discarded; the REQUEST carries the OFFER's ``xid``, the server identifier
  and the requested address (Table 5);
* section 4.4.1 paragraph 8 and 4.4.5 paragraph 4: the lease runs from the time the REQUEST was
  sent (the first transmission of it, the conservative reading), not from the ACK;
* section 4.4.5 paragraph 6: T1 defaults to 0.5 and T2 to 0.875 of the lease, unless options 58 and
  59 give times with T1 < T2 < lease, which section 4.4.5 paragraph 1 requires;
* section 4.4.5 paragraphs 3, 5: RENEWING unicasts a REQUEST with ``ciaddr`` set and no server
  identifier or requested address; REBINDING broadcasts the same;
* section 4.4.5 paragraph 8: a REQUEST with no reply is retried after half the time left to T2
  (half the time left to expiry when REBINDING), but not sooner than 60 seconds;
* section 4.4.5 paragraph 9: lease expiry returns to INIT and drops the address;
* section 3.1 paragraph 19 and section 3.2 paragraph 10: a NAK returns to INIT;
* section 4.1 paragraph 8: DISCOVER and REQUEST retransmit after 4, 8, 16, 32 and then 64 seconds,
  each randomized by -1 to +1 seconds;
* section 4.4.2 paragraph 1: an INIT-REBOOT REQUEST carries the remembered address as the
  requested IP address, has ``ciaddr`` zero and no server identifier, and is broadcast; an ACK with
  its ``xid`` from any server binds, counting the lease from the REQUEST (paragraph 2), and a NAK
  restarts discovery (section 3.2 paragraph 10);
* section 4.4.1 paragraph 6 (Table 5) and paragraph 18, section 4.4.4: DHCPDECLINE has ``ciaddr``
  zero, flags zero, the requested address and the server identifier, and no parameter request list,
  and is broadcast; the client SHOULD wait at least ten seconds before restarting, which
  :attr:`Client4.restart_not_before` records; DHCPRELEASE has ``ciaddr`` set, the server
  identifier and no requested address, and is unicast to the server;
* RFC 6842 section 3 paragraph 4: a message whose client identifier differs from the one this
  client sends is discarded, which includes any identifier when the client sent none.

The retransmission schedule is RFC 2131's, not RFC 9915's, which is DHCPv6 and lives in
:mod:`leasespy.fsm`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Protocol

from .options4 import OPTION_CLIENT_ID, Option4
from .wire4 import BOOTREQUEST, DhcpMessage4, DhcpMessageType

__all__ = [
    "DECLINE_WAIT",
    "Bound",
    "Client4",
    "ClientState",
    "GaveUp",
    "Inform4",
    "Informed",
    "Lost",
    "Rand",
    "Send",
]

OPTION_REQUESTED_IP = 50  # RFC 2132 section 9.1
OPTION_LEASE_TIME = 51  # RFC 2132 section 9.2
OPTION_SERVER_ID = 54  # RFC 2132 section 9.7
OPTION_T1 = 58  # RFC 2132 section 9.11
OPTION_T2 = 59  # RFC 2132 section 9.12
INFINITY = 0xFFFFFFFF  # RFC 2131 section 3.3 paragraph 1: reserved to represent "infinity"
_MIN_RETRY = 60.0  # RFC 2131 section 4.4.5 paragraph 8
_BACKOFF = (4.0, 8.0, 16.0, 32.0, 64.0)  # RFC 2131 section 4.1 paragraph 8
_ZERO = bytes(4)
DECLINE_WAIT = 10.0  # RFC 2131 section 3.1 paragraph 18: "a minimum of ten seconds"
_INFORM_TRIES = 4  # RFC 2131 section 4.4.3 paragraph 4: "60 seconds or 4 tries"
_INFORM_GIVE_UP = 60.0


class ClientState(enum.Enum):
    """The states of RFC 2131 Figure 5 that this machine implements."""

    INIT = "INIT"
    SELECTING = "SELECTING"
    REQUESTING = "REQUESTING"
    BOUND = "BOUND"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"
    REBOOTING = "REBOOTING"


class Rand(Protocol):
    """The two methods of :class:`random.Random` the machine uses."""

    def uniform(self, a: float, b: float) -> float: ...
    def randint(self, a: int, b: int) -> int: ...


@dataclass(frozen=True)
class Send:
    """Transmit ``message``. ``unicast_to`` is the server address, or None to broadcast."""

    message: DhcpMessage4
    unicast_to: bytes | None


@dataclass(frozen=True)
class Bound:
    """Configure ``address`` for ``lease`` seconds from ``leased_at`` (None lease: infinite)."""

    address: bytes
    server_id: bytes
    lease: int
    t1: float | None
    t2: float | None
    leased_at: float


@dataclass(frozen=True)
class Lost:
    """Stop using ``address``: the lease expired or the server NAKed it."""

    address: bytes
    reason: str


@dataclass(frozen=True)
class Informed:
    """A DHCPACK answered the DHCPINFORM: ``options`` are the local configuration parameters."""

    server_id: bytes | None
    options: tuple[Option4, ...]


@dataclass(frozen=True)
class GaveUp:
    """No DHCPACK to a DHCPINFORM in 60 seconds or four tries (RFC 2131 section 4.4.3 para 4)."""

    tries: int


class Client4:
    """One DHCPv4 client on one interface. See the module docstring for the rules."""

    def __init__(
        self,
        chaddr: bytes,
        *,
        rng: Rand,
        htype: int = 1,
        client_id: bytes | None = None,
        parameter_request_list: bytes = b"",
    ) -> None:
        if not 1 <= len(chaddr) <= 16:
            raise ValueError("chaddr is 1 to 16 octets")
        self.chaddr = bytes(chaddr)
        self.htype = htype
        self.client_id = client_id
        self.parameter_request_list = parameter_request_list
        self.state = ClientState.INIT
        self._rng = rng
        self._xid = 0
        self._attempt = 0
        self._deadline: float | None = None
        self._sent_at = 0.0
        self._address = _ZERO
        self._server = _ZERO
        self._offer_address = _ZERO
        self._lease: int | None = None
        self._leased_at = 0.0
        self._t1: float | None = None
        self._t2: float | None = None
        self._expiry: float | None = None
        self._remembered = _ZERO
        self.restart_not_before = 0.0

    # ------------------------------------------------------------------ driving

    @property
    def next_deadline(self) -> float | None:
        """The virtual time at which :meth:`tick` next has something to do, or None."""
        candidates = [
            t for t in (self._deadline, self._t1_due(), self._t2_due(), self._expiry) if t
        ]
        return min(candidates) if candidates else None

    def start(self, now: float) -> list[Send | Bound | Lost]:
        """Leave INIT: broadcast a DHCPDISCOVER (RFC 2131 section 4.4.1).

        Section 4.4.1 paragraph 1 says the client SHOULD wait a random one to ten seconds first
        to desynchronize; that wait is the caller's (:meth:`startup_delay`).
        """
        self._xid = self._rng.randint(0, 0xFFFFFFFF)
        self._attempt = 0
        self.state = ClientState.SELECTING
        return [self._discover(now)]

    def start_reboot(self, now: float, address: bytes) -> list[Send | Bound | Lost]:
        """Leave INIT-REBOOT: broadcast a REQUEST for the remembered ``address`` (section 4.4.2).

        The REQUEST has the address as its requested IP address, ``ciaddr`` zero and no server
        identifier (paragraph 1 and Table 5); the client "records its own local time" for the
        lease, and keeps the same ``xid`` and the section 4.1 retransmission schedule until an ACK
        or a NAK arrives (section 3.2 paragraph 11). Using the old address anyway when nothing
        answers is a MAY the caller decides.
        """
        if len(address) != 4 or address == _ZERO:
            raise ValueError("the remembered address is four octets and not 0.0.0.0")
        self._xid = self._rng.randint(0, 0xFFFFFFFF)
        self._attempt = 0
        self._remembered = bytes(address)
        self._server = _ZERO
        self.state = ClientState.REBOOTING
        return [self._reboot_request(now, first=True)]

    def address_in_use(self, now: float) -> list[Send | Bound | Lost]:
        """The address in the last ACK is already in use: DHCPDECLINE and back to INIT.

        RFC 2131 section 3.1 paragraph 18 and section 4.4.1 paragraph 8: "the client MUST send a
        DHCPDECLINE message to the server and restarts the configuration process", after "a
        minimum of ten seconds"; :attr:`restart_not_before` is that time and :meth:`start` is the
        caller's to call then. Only a client that has just been bound can decline its address.
        """
        if self._address == _ZERO or self.state is not ClientState.BOUND:
            raise ValueError("only a client that has just been bound can decline its address")
        address, server = self._address, self._server
        self._xid = self._rng.randint(0, 0xFFFFFFFF)
        decline = self._bare_message(
            DhcpMessageType.DECLINE,
            (Option4(OPTION_REQUESTED_IP, address), Option4(OPTION_SERVER_ID, server)),
        )
        self.restart_not_before = now + DECLINE_WAIT
        return [Send(decline, None), *self._drop(address, "address in use")]

    def release(self) -> list[Send | Bound | Lost]:
        """Relinquish the lease: a unicast DHCPRELEASE, then INIT (RFC 2131 section 4.4.6).

        Table 5: ``ciaddr`` is the client's address, the server identifier is present and the
        requested IP address is not. Section 4.4.4: unicast to the server. Nothing depends on the
        message arriving (section 4.4.6 paragraph 1), so the machine does not wait for anything.
        """
        if self._address == _ZERO or self.state not in (
            ClientState.BOUND,
            ClientState.RENEWING,
            ClientState.REBINDING,
        ):
            raise ValueError("there is no lease to release")
        address, server = self._address, self._server
        self._xid = self._rng.randint(0, 0xFFFFFFFF)
        release = self._bare_message(
            DhcpMessageType.RELEASE, (Option4(OPTION_SERVER_ID, server),), ciaddr=address
        )
        return [Send(release, server), *self._drop(address, "released")]

    def startup_delay(self) -> float:
        """A random delay of one to ten seconds before the first DISCOVER (section 4.4.1 par. 1)."""
        return self._rng.uniform(1.0, 10.0)

    def receive(self, message: DhcpMessage4, now: float) -> list[Send | Bound | Lost]:
        """Feed one received message; returns the actions it causes (often none)."""
        if message.xid != self._xid or message.op != 2:
            return []
        if not self._client_id_ok(message):
            return []
        try:
            kind = message.message_type
        except ValueError:
            return []
        if kind == DhcpMessageType.OFFER and self.state is ClientState.SELECTING:
            return self._accept_offer(message, now)
        if kind == DhcpMessageType.ACK and self.state in (
            ClientState.REBOOTING,
            ClientState.REQUESTING,
            ClientState.RENEWING,
            ClientState.REBINDING,
        ):
            return self._accept_ack(message)
        if kind == DhcpMessageType.NAK and self.state in (
            ClientState.REBOOTING,
            ClientState.REQUESTING,
            ClientState.RENEWING,
            ClientState.REBINDING,
        ):
            return self._restart(now, "NAK")
        return []

    def tick(self, now: float) -> list[Send | Bound | Lost]:
        """Advance the virtual clock to ``now``: retransmissions, T1, T2 and lease expiry."""
        out: list[Send | Bound | Lost] = []
        if self.state in (ClientState.BOUND, ClientState.RENEWING, ClientState.REBINDING):
            if self._expiry is not None and now >= self._expiry:
                return self._restart(now, "lease expired")
            past_t2 = self._t2 is not None and now >= self._t2
            if self.state is ClientState.BOUND and self._t1 is not None and now >= self._t1:
                # A tick that jumps past T2 goes straight to REBINDING: nobody renews a lease
                # whose renewal window has already closed.
                self.state = ClientState.REBINDING if past_t2 else ClientState.RENEWING
                self._xid = self._rng.randint(0, 0xFFFFFFFF)
                out.append(self._renew(now, unicast=not past_t2))
            elif self.state is ClientState.RENEWING and past_t2:
                self.state = ClientState.REBINDING
                out.append(self._renew(now, unicast=False))
        if (
            self._deadline is not None
            and now >= self._deadline
            and self.state
            in (
                ClientState.SELECTING,
                ClientState.REQUESTING,
                ClientState.REBOOTING,
                ClientState.RENEWING,
                ClientState.REBINDING,
            )
            and not out
        ):
            out.append(self._retransmit(now))
        return out

    # ----------------------------------------------------------------- internals

    def _t1_due(self) -> float | None:
        return self._t1 if self.state is ClientState.BOUND else None

    def _t2_due(self) -> float | None:
        return self._t2 if self.state is ClientState.RENEWING else None

    def _client_id_ok(self, message: DhcpMessage4) -> bool:
        got = message.option(OPTION_CLIENT_ID)
        return got == self.client_id

    def _options(
        self, kind: DhcpMessageType, extra: tuple[Option4, ...] = ()
    ) -> tuple[Option4, ...]:
        options = [Option4(53, bytes([int(kind)]))]
        if self.client_id is not None:
            options.append(Option4(OPTION_CLIENT_ID, self.client_id))
        if self.parameter_request_list:
            options.append(Option4(55, self.parameter_request_list))  # RFC 2132 section 9.8
        options.extend(extra)
        return tuple(options)

    def _message(
        self,
        kind: DhcpMessageType,
        *,
        ciaddr: bytes = _ZERO,
        extra: tuple[Option4, ...] = (),
        broadcast_flag: bool = True,
    ) -> DhcpMessage4:
        return DhcpMessage4(
            op=BOOTREQUEST,
            htype=self.htype,
            hops=0,
            xid=self._xid,
            secs=0,
            flags=0x8000 if broadcast_flag else 0,
            ciaddr=ciaddr,
            yiaddr=_ZERO,
            siaddr=_ZERO,
            giaddr=_ZERO,
            chaddr=self.chaddr,
            options=self._options(kind, extra),
        )

    def _delay(self) -> float:
        base = _BACKOFF[min(self._attempt, len(_BACKOFF) - 1)]
        self._attempt += 1
        return max(0.0, base + self._rng.uniform(-1.0, 1.0))

    def _discover(self, now: float) -> Send:
        self._sent_at = now
        self._deadline = now + self._delay()
        return Send(self._message(DhcpMessageType.DISCOVER), None)

    def _bare_message(
        self, kind: DhcpMessageType, extra: tuple[Option4, ...], *, ciaddr: bytes = _ZERO
    ) -> DhcpMessage4:
        """A DECLINE or RELEASE: flags zero and no parameter request list (Table 5)."""
        options = [Option4(53, bytes([int(kind)]))]
        if self.client_id is not None:
            options.append(Option4(OPTION_CLIENT_ID, self.client_id))
        options.extend(extra)
        return DhcpMessage4(
            op=BOOTREQUEST,
            htype=self.htype,
            hops=0,
            xid=self._xid,
            secs=0,
            flags=0,
            ciaddr=ciaddr,
            yiaddr=_ZERO,
            siaddr=_ZERO,
            giaddr=_ZERO,
            chaddr=self.chaddr,
            options=tuple(options),
        )

    def _drop(self, address: bytes, reason: str) -> list[Send | Bound | Lost]:
        self._address = _ZERO
        self._t1 = self._t2 = self._expiry = self._deadline = None
        self._lease = None
        self.state = ClientState.INIT
        return [Lost(address, reason)]

    def _reboot_request(self, now: float, *, first: bool) -> Send:
        if first:
            self._sent_at = now  # the lease counts from the first REQUEST (section 4.4.2 para 2)
        self._deadline = now + self._delay()
        extra = (Option4(OPTION_REQUESTED_IP, self._remembered),)
        return Send(self._message(DhcpMessageType.REQUEST, extra=extra), None)

    def _request_selecting(self) -> Send:
        extra = (
            Option4(OPTION_REQUESTED_IP, self._offer_address),
            Option4(OPTION_SERVER_ID, self._server),
        )
        return Send(self._message(DhcpMessageType.REQUEST, extra=extra), None)

    def _accept_offer(self, message: DhcpMessage4, now: float) -> list[Send | Bound | Lost]:
        server = message.option(OPTION_SERVER_ID)
        if server is None or len(server) != 4 or message.yiaddr == _ZERO:
            return []
        self._server, self._offer_address = server, message.yiaddr
        self.state = ClientState.REQUESTING
        self._attempt = 0
        self._sent_at = now
        self._deadline = now + self._delay()
        return [self._request_selecting()]

    def _renew(self, now: float, *, unicast: bool) -> Send:
        # Section 4.4.5 paragraphs 3 and 5: ciaddr set, no server identifier, no requested address
        # (Table 5). A fresh REQUEST is a fresh transmission, so the lease clock restarts here.
        self._sent_at = now
        self._attempt = 0
        self._deadline = now + self._retry_wait(now)
        message = self._message(DhcpMessageType.REQUEST, ciaddr=self._address, broadcast_flag=False)
        return Send(message, self._server if unicast and self._server != _ZERO else None)

    def _retry_wait(self, now: float) -> float:
        end = self._t2 if self.state is ClientState.RENEWING else self._expiry
        remaining = (end - now) if end is not None else _MIN_RETRY
        return max(_MIN_RETRY, remaining / 2)

    def _retransmit(self, now: float) -> Send:
        if self.state is ClientState.SELECTING:
            self._deadline = now + self._delay()
            return Send(self._message(DhcpMessageType.DISCOVER), None)
        if self.state is ClientState.REQUESTING:
            self._deadline = now + self._delay()
            return self._request_selecting()
        if self.state is ClientState.REBOOTING:
            return self._reboot_request(now, first=False)
        self._deadline = now + self._retry_wait(now)
        message = self._message(DhcpMessageType.REQUEST, ciaddr=self._address, broadcast_flag=False)
        renewing = self.state is ClientState.RENEWING and self._server != _ZERO
        return Send(message, self._server if renewing else None)

    def _accept_ack(self, message: DhcpMessage4) -> list[Send | Bound | Lost]:
        raw = message.option(OPTION_LEASE_TIME)
        if raw is None or len(raw) != 4:
            return []
        lease = int.from_bytes(raw, "big")
        if message.yiaddr == _ZERO:
            return []
        server = message.option(OPTION_SERVER_ID) or self._server
        self._address, self._server = message.yiaddr, server
        self._lease = None if lease == INFINITY else lease
        self._leased_at = self._sent_at
        self._attempt = 0
        self._deadline = None
        if self._lease is None:
            self._t1 = self._t2 = self._expiry = None
        else:
            self._t1, self._t2 = self._timers(message, lease)
            self._expiry = self._leased_at + lease
        self.state = ClientState.BOUND
        return [Bound(self._address, server, lease, self._t1, self._t2, self._leased_at)]

    def _timers(self, message: DhcpMessage4, lease: int) -> tuple[float, float]:
        t1 = self._u32(message.option(OPTION_T1))
        t2 = self._u32(message.option(OPTION_T2))
        if t1 is not None and t2 is not None and 0 < t1 < t2 < lease:
            return self._leased_at + t1, self._leased_at + t2
        # Section 4.4.5 paragraph 6 defaults; also the fallback when the server's times break the
        # T1 < T2 < expiry ordering of paragraph 1.
        return self._leased_at + 0.5 * lease, self._leased_at + 0.875 * lease

    @staticmethod
    def _u32(raw: bytes | None) -> int | None:
        return int.from_bytes(raw, "big") if raw is not None and len(raw) == 4 else None

    def _restart(self, now: float, reason: str) -> list[Send | Bound | Lost]:
        out: list[Send | Bound | Lost] = []
        if self._address != _ZERO:
            out.append(Lost(self._address, reason))
        elif self.state is ClientState.REBOOTING:
            out.append(Lost(self._remembered, reason))  # the remembered address cannot be reused
        self._address = _ZERO
        self._t1 = self._t2 = self._expiry = None
        self.state = ClientState.INIT
        out.extend(self.start(now))
        return out


class Inform4:
    """DHCPINFORM for a client whose address is configured some other way (RFC 2131 section 4.4.3).

    The message has ``ciaddr`` set to the client's address, a parameter request list if given, and
    neither a requested IP address, a lease time nor a server identifier (Table 5). It is unicast
    to ``server`` when that is known and broadcast otherwise (paragraph 2). An ACK with the same
    ``xid`` finishes the exchange (paragraph 3); with none after 60 seconds or four tries, the
    machine says so with :class:`GaveUp` (paragraph 4), and what to do next is the caller's.
    The retransmission schedule is section 4.1's: 4, 8, 16 and 32 seconds, each randomized.
    """

    def __init__(
        self,
        chaddr: bytes,
        address: bytes,
        *,
        rng: Rand,
        htype: int = 1,
        client_id: bytes | None = None,
        parameter_request_list: bytes = b"",
        server: bytes | None = None,
    ) -> None:
        if not 1 <= len(chaddr) <= 16:
            raise ValueError("chaddr is 1 to 16 octets")
        if len(address) != 4 or address == _ZERO:
            raise ValueError("DHCPINFORM needs the client's own configured address")
        self.chaddr, self.address, self.htype = bytes(chaddr), bytes(address), htype
        self.client_id = client_id
        self.parameter_request_list = parameter_request_list
        self.server = server
        self.done = False
        self._rng = rng
        self._xid = 0
        self._tries = 0
        self._started = 0.0
        self._deadline: float | None = None

    @property
    def next_deadline(self) -> float | None:
        """The virtual time at which :meth:`tick` next has something to do, or None."""
        return self._deadline

    def start(self, now: float) -> list[Send | Informed | GaveUp]:
        """Send the first DHCPINFORM."""
        self._xid = self._rng.randint(0, 0xFFFFFFFF)
        self._started = now
        self._tries = 0
        self.done = False
        return [self._send(now)]

    def receive(self, message: DhcpMessage4, now: float) -> list[Send | Informed | GaveUp]:  # noqa: ARG002
        """An ACK with this exchange's ``xid`` and client identifier ends it."""
        if self.done or message.xid != self._xid or message.op != 2:
            return []
        if message.option(OPTION_CLIENT_ID) != self.client_id:
            return []
        try:
            kind = message.message_type
        except ValueError:
            return []
        if kind != DhcpMessageType.ACK:
            return []
        self.done = True
        self._deadline = None
        return [Informed(message.option(OPTION_SERVER_ID), message.options)]

    def tick(self, now: float) -> list[Send | Informed | GaveUp]:
        """Retransmit, or give up after four tries or 60 seconds."""
        if self.done or self._deadline is None or now < self._deadline:
            return []
        if self._tries >= _INFORM_TRIES or now - self._started >= _INFORM_GIVE_UP:
            self.done = True
            self._deadline = None
            return [GaveUp(self._tries)]
        return [self._send(now)]

    def _send(self, now: float) -> Send:
        base = _BACKOFF[min(self._tries, len(_BACKOFF) - 1)]
        self._tries += 1
        self._deadline = now + max(0.0, base + self._rng.uniform(-1.0, 1.0))
        options = [Option4(53, bytes([int(DhcpMessageType.INFORM)]))]
        if self.client_id is not None:
            options.append(Option4(OPTION_CLIENT_ID, self.client_id))
        if self.parameter_request_list:
            options.append(Option4(55, self.parameter_request_list))  # RFC 2132 section 9.8
        message = DhcpMessage4(
            op=BOOTREQUEST,
            htype=self.htype,
            hops=0,
            xid=self._xid,
            secs=0,
            flags=0,
            ciaddr=self.address,
            yiaddr=_ZERO,
            siaddr=_ZERO,
            giaddr=_ZERO,
            chaddr=self.chaddr,
            options=tuple(options),
        )
        return Send(message, self.server)
