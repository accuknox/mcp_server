"""
Time helpers for the CWPP APIs.

Every CWPP time field is epoch SECONDS (10 digits), never milliseconds. These
helpers accept whatever a caller is likely to say — "last 24 hours", "7d",
"today", an ISO date, or an epoch in seconds or millis — and normalise it.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

_DURATION_UNITS = {
    "s": 1,
    "sec": 1,
    "second": 1,
    "m": 60,
    "min": 60,
    "minute": 60,
    "h": 3600,
    "hr": 3600,
    "hour": 3600,
    "d": 86400,
    "day": 86400,
    "w": 604800,
    "week": 604800,
    "mo": 2592000,
    "month": 2592000,
    "y": 31536000,
    "year": 31536000,
}

_DURATION_RE = re.compile(r"^(\d+)?\s*([a-z]+)$")

DEFAULT_RANGE_SECONDS = 24 * 3600


def now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _normalize_epoch(value: float) -> int:
    """Collapse milliseconds/microseconds to epoch seconds."""
    value = float(value)
    while value > 1e11:  # 1e11 sec ≈ year 5138, so anything above is ms/µs
        value /= 1000.0
    return int(value)


def parse_duration(text: Optional[str]) -> Optional[int]:
    """Parse "24h", "last 7 days", "30 minutes", "1w" → seconds. None if unparseable."""
    if not text:
        return None

    cleaned = str(text).strip().lower()
    for noise in ("last", "past", "previous", "prev", "ago", "-", "the"):
        cleaned = cleaned.replace(noise, " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    match = _DURATION_RE.match(cleaned.replace(" ", ""))
    if not match:
        # "7 days" style (digits and unit separated)
        match = re.match(r"^(\d+)\s*([a-z]+)$", cleaned)
    if not match:
        return None

    amount = int(match.group(1) or 1)
    unit = match.group(2)
    seconds = _DURATION_UNITS.get(unit) or _DURATION_UNITS.get(unit.rstrip("s"))
    if not seconds:
        return None
    return amount * seconds


def parse_timestamp(value: Any) -> Optional[int]:
    """Parse an epoch (s/ms), ISO date/datetime, "now", or a relative duration.

    A relative value ("24h", "last 7 days") is resolved as *now minus that
    duration*, which is what a caller means by from_time="7d".
    """
    if value is None or value == "" or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return _normalize_epoch(value)

    text = str(value).strip()
    if not text:
        return None

    if text.lower() in ("now", "today's date", "current"):
        return now_epoch()

    if re.fullmatch(r"\d+(\.\d+)?", text):
        return _normalize_epoch(float(text))

    iso_candidate = text.replace("Z", "+00:00")
    if "T" not in iso_candidate and " " in iso_candidate:
        iso_candidate = iso_candidate.replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return int(
                datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp(),
            )
        except ValueError:
            continue

    duration = parse_duration(text)
    if duration:
        return now_epoch() - duration

    return None


def utc_midnight(ts: int) -> int:
    day = datetime.fromtimestamp(ts, tz=timezone.utc).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    return int(day.timestamp())


def resolve_time_range(
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    default_seconds: int = DEFAULT_RANGE_SECONDS,
    default_from: Optional[int] = None,
) -> Tuple[Optional[int], Optional[int], Optional[dict]]:
    """Resolve caller-friendly time inputs to (from_epoch_seconds, to_epoch_seconds).

    Precedence: explicit from_time/to_time win; otherwise `period` is applied
    relative to to_time (default: now); otherwise `default_from` if given, else
    `default_seconds` back from to_time.

    Returns (from_ts, to_ts, error_dict) — error_dict is None on success.
    """
    now = now_epoch()

    to_ts = parse_timestamp(to_time)
    if to_time and to_ts is None:
        return None, None, {
            "error": f"Could not parse to_time '{to_time}'.",
            "hint": "Use an ISO date/datetime (2026-08-10 or 2026-08-10T12:00:00Z), an epoch, or 'now'.",
        }
    if to_ts is None:
        to_ts = now

    from_ts = parse_timestamp(from_time)
    if from_time and from_ts is None:
        return None, None, {
            "error": f"Could not parse from_time '{from_time}'.",
            "hint": "Use an ISO date/datetime, an epoch, or a relative window like '24h' / 'last 7 days'.",
        }

    if from_ts is None:
        period_text = (period or "").strip().lower()
        if period_text in ("today",):
            from_ts = utc_midnight(now)
        elif period_text in ("yesterday",):
            midnight = utc_midnight(now)
            from_ts, to_ts = midnight - 86400, midnight
        elif period_text:
            duration = parse_duration(period_text)
            if not duration:
                return None, None, {
                    "error": f"Could not parse period '{period}'.",
                    "hint": "Examples: 'last 24 hours', '7d', '30 minutes', 'today', 'yesterday'.",
                }
            from_ts = to_ts - duration
        elif default_from is not None:
            from_ts = default_from
        else:
            from_ts = to_ts - default_seconds

    if from_ts > to_ts:
        from_ts, to_ts = to_ts, from_ts

    return from_ts, to_ts, None


def iso(ts: Optional[int]) -> Optional[str]:
    """Epoch seconds → ISO-8601 UTC string (for readable tool output)."""
    if ts is None:
        return None
    return (
        datetime.fromtimestamp(int(ts), tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def time_range_info(from_ts: int, to_ts: int) -> Dict[str, Any]:
    return {
        "from": from_ts,
        "to": to_ts,
        "from_iso": iso(from_ts),
        "to_iso": iso(to_ts),
    }
