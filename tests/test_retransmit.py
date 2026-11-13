"""The retransmission schedule of RFC 9915 sec. 15 with the Table 1 values of sec. 7.6.

The expected sequences are derived by hand from the formulas in sec. 15, not from the code.
"""

from __future__ import annotations

import dataclasses
from itertools import islice

import pytest

from leasespy.fsm import (
    CONFIRM,
    DECLINE,
    INFORMATION_REQUEST,
    RELEASE,
    RENEW,
    REQUEST,
    RetransmitParams,
    Retransmitter,
    retransmission_schedule,
)


def zero() -> float:
    return 0.0


def test_request_schedule_rand_zero():
    # IRT 1, doubling, capped at REQ_MAX_RT 30, REQ_MAX_RC 10 transmissions.
    assert list(retransmission_schedule(REQUEST, zero)) == [1, 2, 4, 8, 16, 30, 30, 30, 30, 30]
    timer = Retransmitter(REQUEST, zero)
    for _ in range(10):
        assert timer.next_timeout(0.0) is not None
    assert timer.next_timeout(0.0) is None


def test_first_timeout_uses_irt_with_rand():
    assert Retransmitter(REQUEST, lambda: 0.1).next_timeout(0) == pytest.approx(1.1)
    assert Retransmitter(REQUEST, lambda: -0.1).next_timeout(0) == pytest.approx(0.9)


def test_doubling_uses_previous_rt_including_rand():
    rands = iter([0.1, -0.1, 0.05])
    timer = Retransmitter(REQUEST, lambda: next(rands))
    first = timer.next_timeout(0)
    second = timer.next_timeout(0)
    third = timer.next_timeout(0)
    assert first == pytest.approx(1.1)
    assert second == pytest.approx(2 * 1.1 - 0.1 * 1.1)
    assert third == pytest.approx(2 * second + 0.05 * second)


def test_cap_applies_mrt_plus_rand_mrt():
    # 1, 2, 4, 8, 16 then 32 exceeds 30, so the sixth is 30 + 0.1*30; the cap is not re-clamped.
    values = list(islice(retransmission_schedule(REQUEST, lambda: 0.1), 10))
    assert values[5:] == [pytest.approx(33.0)] * 5


def test_mrt_zero_is_uncapped():
    params = RetransmitParams(irt=1.0, mrc=12)
    assert list(retransmission_schedule(params, zero))[-1] == 2048


def test_confirm_stops_at_mrd_not_mrc():
    # CNF_TIMEOUT 1, CNF_MAX_RT 4, MRD 10, MRC 0: 1, 2, 4, 4 (elapsed 11 >= 10, stop).
    assert list(retransmission_schedule(CONFIRM, zero)) == [1, 2, 4, 4]
    timer = Retransmitter(CONFIRM, zero)
    assert timer.next_timeout(0) == 1
    assert timer.next_timeout(9.99) == 2
    assert timer.next_timeout(10.0) is None


def test_release_fails_after_four_transmissions():
    assert list(retransmission_schedule(RELEASE, zero)) == [1, 2, 4, 8]
    assert list(retransmission_schedule(DECLINE, zero)) == [1, 2, 4, 8]


def test_both_limits_zero_never_fails():
    values = list(islice(retransmission_schedule(INFORMATION_REQUEST, zero), 50))
    assert len(values) == 50
    assert values[-1] == 3600


def test_both_limits_nonzero_either_fails_it():
    params = RetransmitParams(irt=1.0, mrt=0, mrc=10, mrd=5.0)
    assert list(retransmission_schedule(params, zero)) == [1, 2, 4]  # 1+2+4 = 7 >= 5
    params = RetransmitParams(irt=1.0, mrt=0, mrc=2, mrd=1000.0)
    assert list(retransmission_schedule(params, zero)) == [1, 2]


def test_renew_takes_its_mrd_from_the_caller():
    assert RENEW.mrd == 0
    params = dataclasses.replace(RENEW, mrd=25.0)
    assert list(retransmission_schedule(params, zero)) == [10, 20]


@pytest.mark.parametrize("bad", [0.5, -0.5, 0.100001, float("nan")])
def test_rand_out_of_range_rejected(bad):
    with pytest.raises(ValueError, match="RAND"):
        Retransmitter(REQUEST, lambda: bad).next_timeout(0)


def test_deterministic_given_rand_sequence():
    def run() -> list[float]:
        rands = iter([0.01, -0.02, 0.03, 0.0, 0.1, -0.1, 0.05, 0.0, 0.0, 0.0])
        return list(retransmission_schedule(REQUEST, lambda: next(rands)))

    assert run() == run()
    assert len(run()) == 10


def test_table_1_constants():
    assert (REQUEST.irt, REQUEST.mrt, REQUEST.mrc, REQUEST.mrd) == (1, 30, 10, 0)
    assert (CONFIRM.irt, CONFIRM.mrt, CONFIRM.mrc, CONFIRM.mrd) == (1, 4, 0, 10)
    assert (RENEW.irt, RENEW.mrt) == (10, 600)
    assert (INFORMATION_REQUEST.irt, INFORMATION_REQUEST.mrt) == (1, 3600)
    assert (RELEASE.irt, RELEASE.mrt, RELEASE.mrc) == (1, 0, 4)
    assert (DECLINE.irt, DECLINE.mrt, DECLINE.mrc) == (1, 0, 4)
