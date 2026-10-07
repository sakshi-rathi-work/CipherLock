"""In-memory brute-force lockout module for CipherLock.

Per Phase 2 specification P9:
- Key: (normalised_email, request.remote_addr).
- Counts failures for nonexistent emails too (avoids email enumeration).
- Failures 1-5 return 401. The 5th failure starts a 300-second lockout.
- While locked, every attempt returns 429 with retry_after and Retry-After header.
- Attempts during lockout do NOT extend it.
- Failure counter resets if last failure is older than 300 seconds.
- Successful login deletes that key's state.
- Module-level dict guarded by threading.Lock, opportunistically pruned.
- Clock is injectable (_now) and reset_all() is provided for test isolation.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, NamedTuple

LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_SECONDS = 300
MAX_TRACKED_ENTRIES = 5000

# Clock injection for deterministic testing without sleeping
_now: Callable[[], float] = time.time


class _AttemptState(NamedTuple):
    count: int
    first_failed_at: float
    last_failed_at: float
    locked_until: float | None


_lock = threading.Lock()
_state: dict[tuple[str, str], _AttemptState] = {}


def set_clock(clock_fn: Callable[[], float]) -> None:
    """Inject a custom clock function (used in tests to fast-forward time)."""
    global _now
    _now = clock_fn


def reset_clock() -> None:
    """Reset clock to system time."""
    global _now
    _now = time.time


def reset_all() -> None:
    """Reset all lockout state (used in test fixtures)."""
    with _lock:
        _state.clear()


def _prune_expired_locked(current_time: float) -> None:
    """Prune expired entries if the state dictionary grows too large."""
    if len(_state) <= MAX_TRACKED_ENTRIES:
        return
    expired_keys = [
        k for k, v in _state.items()
        if (v.locked_until and current_time >= v.locked_until)
        or (not v.locked_until and current_time - v.last_failed_at > LOCKOUT_DURATION_SECONDS)
    ]
    for k in expired_keys:
        _state.pop(k, None)


def is_locked(email: str, ip: str) -> tuple[bool, int]:
    """Check if the given (email, ip) pair is currently locked out.

    Returns:
        (is_locked, retry_after_seconds)
    """
    key = (email.strip().lower(), ip.strip())
    current_time = _now()

    with _lock:
        entry = _state.get(key)
        if not entry:
            return False, 0

        if entry.locked_until is not None:
            if current_time < entry.locked_until:
                retry_after = max(1, int(entry.locked_until - current_time))
                return True, retry_after
            else:
                # Lockout expired
                _state.pop(key, None)
                return False, 0

        # If failures are older than duration, reset
        if current_time - entry.last_failed_at > LOCKOUT_DURATION_SECONDS:
            _state.pop(key, None)
            return False, 0

        return False, 0


def record_failure(email: str, ip: str) -> tuple[bool, int]:
    """Record a failed login attempt for the (email, ip) pair.

    Returns:
        (is_now_locked, retry_after_seconds)
    """
    key = (email.strip().lower(), ip.strip())
    current_time = _now()

    with _lock:
        _prune_expired_locked(current_time)
        entry = _state.get(key)

        if entry is None or (current_time - entry.last_failed_at > LOCKOUT_DURATION_SECONDS and entry.locked_until is None):
            # First failure or expired prior failure window
            _state[key] = _AttemptState(
                count=1,
                first_failed_at=current_time,
                last_failed_at=current_time,
                locked_until=None,
            )
            return False, 0

        # If already locked, do NOT extend lockout duration (avoids indefinite DoS)
        if entry.locked_until is not None:
            if current_time < entry.locked_until:
                retry_after = max(1, int(entry.locked_until - current_time))
                return True, retry_after
            else:
                # Expired lock, starting new failure cycle
                _state[key] = _AttemptState(
                    count=1,
                    first_failed_at=current_time,
                    last_failed_at=current_time,
                    locked_until=None,
                )
                return False, 0

        # Increment failure count
        new_count = entry.count + 1
        if new_count >= LOCKOUT_THRESHOLD:
            # 5th failure triggers lockout of 300 seconds
            locked_until = current_time + LOCKOUT_DURATION_SECONDS
            _state[key] = _AttemptState(
                count=new_count,
                first_failed_at=entry.first_failed_at,
                last_failed_at=current_time,
                locked_until=locked_until,
            )
            return True, LOCKOUT_DURATION_SECONDS
        else:
            _state[key] = _AttemptState(
                count=new_count,
                first_failed_at=entry.first_failed_at,
                last_failed_at=current_time,
                locked_until=None,
            )
            return False, 0


def reset_key(email: str, ip: str) -> None:
    """Reset the failure/lockout state on successful login."""
    key = (email.strip().lower(), ip.strip())
    with _lock:
        _state.pop(key, None)
