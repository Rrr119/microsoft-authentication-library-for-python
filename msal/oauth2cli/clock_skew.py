"""Clock skew detection and correction.

When a device clock drifts (e.g. by half an hour), token requests can fail
with confusing errors, and freshly cached tokens can be considered expired
(or valid for too long) because their timestamps are computed from the
local clock. This module detects the offset between the local clock and the
identity server's clock (based on the HTTP ``Date`` response header) and
provides a corrected "now" that callers can use for cache bookkeeping.
"""

import logging
import time
from email.utils import parsedate_tz, mktime_tz


logger = logging.getLogger(__name__)


def _get_header_case_insensitive(headers, name):
    if not headers:
        return None
    getter = getattr(headers, "get", None)
    if getter:
        value = getter(name)  # requests' CaseInsensitiveDict handles casing
        if value:
            return value
    items = headers.items() if hasattr(headers, "items") else []
    lowered = name.lower()
    for key, value in items:
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return None


def _parse_http_date(value):
    """Parse an HTTP Date header into epoch seconds. Return None on failure."""
    try:
        parsed = parsedate_tz(value)
        if parsed is None:
            return None
        return mktime_tz(parsed)
    except (TypeError, ValueError, OverflowError):
        return None


# AADSTS error codes whose root cause is typically a wrong device clock.
_CLOCK_SKEW_ERROR_CODES = (
    "AADSTS50013",   # Assertion is not within its valid time range
    "AADSTS700024",  # Client assertion is not within its valid time range
    "AADSTS700025",  # Client assertion time-related validation failure
    )

_CLOCK_SKEW_KEYWORDS = (
    "clock",
    "not yet valid",
    "valid time range",
    "lifetime validation",
    )


def is_clock_skew_error(response):
    """Return True if an OAuth2 error response smells like a clock skew issue."""
    if not isinstance(response, dict):
        return False
    haystack = " ".join(str(response.get(k) or "") for k in (
        "error", "error_description", "error_uri"))
    if any(code in haystack for code in _CLOCK_SKEW_ERROR_CODES):
        return True
    lowered = haystack.lower()
    return any(keyword in lowered for keyword in _CLOCK_SKEW_KEYWORDS)


class ClockSkewCorrector(object):
    """Learns the local clock's offset from the server and corrects for it.

    The corrector observes the ``Date`` header of each HTTP response.
    Only offsets whose absolute value reaches ``threshold_seconds`` are
    applied; smaller offsets are ignored so that the normal code path
    (a reasonably accurate device clock) behaves exactly as before.
    """

    DEFAULT_THRESHOLD_SECONDS = 120  # Ignore sub-2-minute jitter

    def __init__(self, threshold_seconds=DEFAULT_THRESHOLD_SECONDS):
        self._threshold_seconds = threshold_seconds
        self._skew_seconds = 0  # server_time - local_time, as last measured

    @property
    def skew_seconds(self):
        """The most recently measured offset (server time minus local time)."""
        return self._skew_seconds

    @property
    def correction_active(self):
        """True when the measured skew is large enough to be worth correcting."""
        return abs(self._skew_seconds) >= self._threshold_seconds

    def now(self):
        """Current timestamp, corrected when a significant skew was detected.

        Returns exactly ``time.time()`` when no significant skew has been
        observed, so the normal path is unaffected.
        """
        return time.time() + (
            self._skew_seconds if self.correction_active else 0)

    def observe_response_headers(self, headers):
        """Learn the clock skew from a response's Date header, if present.

        Returns True when a usable Date header was found, False otherwise.
        """
        date_value = _get_header_case_insensitive(headers, "Date")
        if not date_value:
            return False
        server_epoch = _parse_http_date(date_value)
        if server_epoch is None:
            return False
        skew = int(server_epoch - time.time())
        if skew != self._skew_seconds:
            self._skew_seconds = skew
            if self.correction_active:
                logger.warning(
                    "Device clock appears to be off by %+d seconds. "
                    "Applying automatic clock skew correction; "
                    "consider synchronizing the device clock (e.g. via NTP).",
                    skew)
        return True
