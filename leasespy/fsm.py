"""client and server state machines with retransmission (RFC 9915 sec. 14, sec. 15, sec. 18).

The retransmission algorithm of RFC 9915 sec. 15 is implemented as pure arithmetic with an
injected random source (:class:`Retransmitter`, :func:`retransmission_schedule`). The state
machine itself (:func:`client_step`) is not, and still raises.

The Solicit variant of sec. 18.2.1 (first RT strictly greater than IRT, collect Advertise
messages) is not implemented here. Reconfigure retransmission is a server behaviour that
sec. 18.3.11 describes separately, so it has no constant in this module.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ClientState = Any  # placeholder: give it a real type in the milestone that needs it
    Event = Any  # placeholder: give it a real type in the milestone that needs it
    Step = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CONFIRM",
    "DECLINE",
    "INFORMATION_REQUEST",
    "REBIND",
    "RELEASE",
    "RENEW",
    "REQUEST",
    "RetransmitParams",
    "Retransmitter",
    "client_step",
    "retransmission_schedule",
]

RAND_BOUND = 0.1  # RFC 9915 sec. 15: RAND is uniform between -0.1 and +0.1


@dataclass(frozen=True, slots=True)
class RetransmitParams:
    """IRT, MRT, MRC and MRD of RFC 9915 sec. 15; a zero MRT, MRC or MRD means no limit."""

    irt: float
    mrt: float = 0.0
    mrc: int = 0
    mrd: float = 0.0


# RFC 9915 sec. 7.6 Table 1, joined to the per-message parameters of sec. 18.2.
REQUEST = RetransmitParams(irt=1.0, mrt=30.0, mrc=10)  # sec. 18.2.2: REQ_*
CONFIRM = RetransmitParams(irt=1.0, mrt=4.0, mrd=10.0)  # sec. 18.2.3: CNF_*, MRD is CNF_MAX_RD
# sec. 18.2.4 and sec. 18.2.5 set MRD from the lease times, not from Table 1: the caller
# supplies it with dataclasses.replace(RENEW, mrd=...).
RENEW = RetransmitParams(irt=10.0, mrt=600.0)  # sec. 18.2.4: REN_*
REBIND = RetransmitParams(irt=10.0, mrt=600.0)  # sec. 18.2.5: REB_*
INFORMATION_REQUEST = RetransmitParams(irt=1.0, mrt=3600.0)  # sec. 18.2.6: INF_*
RELEASE = RetransmitParams(irt=1.0, mrc=4)  # sec. 18.2.7: REL_*, MRT is 0
DECLINE = RetransmitParams(irt=1.0, mrc=4)  # sec. 18.2.8: DEC_*, MRT is 0


class Retransmitter:
    """The sec. 15 timeout sequence for one exchange.

    Call :meth:`next_timeout` before each transmission, the first included, with the seconds
    elapsed since the first transmission. It returns the RT to wait for that transmission, or
    None once the exchange has failed. ``rand`` is called once per RT and must return a value
    in [-0.1, +0.1]; anything else raises ``ValueError`` rather than being accepted.
    """

    def __init__(self, params: RetransmitParams, rand: Callable[[], float]) -> None:
        self._params = params
        self._rand = rand
        self._count = 0
        self._previous = 0.0

    @property
    def transmissions(self) -> int:
        """How many timeouts have been handed out, one per transmission."""
        return self._count

    def _draw(self) -> float:
        value = self._rand()
        if not -RAND_BOUND <= value <= RAND_BOUND:
            raise ValueError(f"RAND must lie in [-0.1, +0.1], got {value!r}")
        return value

    def next_timeout(self, elapsed: float) -> float | None:
        """The RT for the next transmission, or None when the exchange has failed."""
        params = self._params
        if params.mrc and self._count >= params.mrc:
            return None
        if params.mrd and elapsed >= params.mrd:
            return None
        rand = self._draw()
        if self._count == 0:
            rt = params.irt + rand * params.irt  # sec. 15: RT = IRT + RAND*IRT
        else:
            rt = 2 * self._previous + rand * self._previous  # RT = 2*RTprev + RAND*RTprev
        if params.mrt and rt > params.mrt:
            rt = params.mrt + rand * params.mrt  # if RT > MRT then RT = MRT + RAND*MRT
        self._count += 1
        self._previous = rt
        return rt


def retransmission_schedule(params: RetransmitParams, rand: Callable[[], float]) -> Iterator[float]:
    """Yield every RT of an exchange in which no response ever arrives (RFC 9915 sec. 15).

    Each wait is assumed to run to its end, so the elapsed time passed to the MRD check is the
    sum of the timeouts so far. Finite unless MRC and MRD are both zero, where sec. 15 says the
    client transmits until it gets a response.
    """
    timer = Retransmitter(params, rand)
    elapsed = 0.0
    while (timeout := timer.next_timeout(elapsed)) is not None:
        yield timeout
        elapsed += timeout


def client_step(state: ClientState, event: Event, now: float) -> Step:
    """Pending behaviour defined by RFC 9915 sec. 18.

    Not implemented yet. See the ``fsm.client_step()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("client_step() is not implemented: RFC 9915 sec. 18")
