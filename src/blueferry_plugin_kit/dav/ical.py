"""Turn iCalendar objects into the occurrences of a time window.

Needs the ``caldav`` extra (icalendar, recurring-ical-events,
x-wr-timezone); the libraries are imported on first use.

Recurring events are expanded with ``recurring-ical-events`` (RRULE, RDATE,
EXDATE and overridden instances via RECURRENCE-ID). Times with a TZID are
converted to the local zone; floating times are read as local time; all-day
events cover their dates in the local zone. Calendars that only name their
zone in ``X-WR-TIMEZONE`` (Google exports) are normalized first.
"""
from __future__ import annotations

import hashlib
import logging
import os
import urllib.parse
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import date, datetime, time, timedelta, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from blueferry_plugin_kit._extras import need

if TYPE_CHECKING:
    import icalendar

log = logging.getLogger(__name__)
MAX_TEXT = 200
MAX_OCCURRENCES = 500


@dataclass(frozen=True, slots=True)
class Occurrence:
    key: str          # stable id of this instance (hash; no content)
    title: str
    start: str        # ISO 8601 with offset
    end: str
    all_day: bool
    location: str
    url: str          # http(s) link of the event, or ""
    calendar: str     # calendar display name

    @property
    def start_at(self) -> datetime:
        return datetime.fromisoformat(self.start)

    @property
    def end_at(self) -> datetime:
        return datetime.fromisoformat(self.end)

    def to_json(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_json(cls, raw: object) -> Occurrence | None:
        if not isinstance(raw, dict):
            return None
        try:
            item = cls(
                key=str(raw["key"]), title=str(raw["title"]), start=str(raw["start"]),
                end=str(raw["end"]), all_day=bool(raw["all_day"]),
                location=str(raw.get("location", "")), url=str(raw.get("url", "")),
                calendar=str(raw.get("calendar", "")),
            )
            if item.start_at.tzinfo is None or item.end_at.tzinfo is None:
                return None
        except (KeyError, TypeError, ValueError):
            return None
        return item


def local_zone() -> tzinfo:
    """The desktop's zone: ``TZ``, ``/etc/localtime`` or ``/etc/timezone``."""
    candidates = []
    if os.environ.get("TZ"):
        candidates.append(os.environ["TZ"].lstrip(":"))
    try:
        target = os.readlink("/etc/localtime")
        if "zoneinfo/" in target:
            candidates.append(target.split("zoneinfo/", 1)[1])
    except OSError:
        pass
    try:
        candidates.append(Path("/etc/timezone").read_text(encoding="utf-8").strip())
    except OSError:
        pass
    for name in candidates:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            continue
    return datetime.now().astimezone().tzinfo or ZoneInfo("UTC")


def _text(value: object) -> str:
    text = str(value or "")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(text.split())[:MAX_TEXT]


def _link(value: object) -> str:
    text = str(value or "").strip()
    parts = urllib.parse.urlsplit(text)
    if parts.scheme in ("http", "https") and parts.hostname and len(text) <= 2048:
        return text
    return ""


def _moment(value: object, zone: tzinfo) -> tuple[datetime, bool]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=zone), False
        return value.astimezone(zone), False
    if isinstance(value, date):
        return datetime.combine(value, time(), tzinfo=zone), True
    raise ValueError("no time")


def occurrences(
    texts: Iterable[str], start: datetime, end: datetime, zone: tzinfo, *, calendar: str = "",
    calendar_id: str = "",
) -> list[Occurrence]:
    """Every event instance overlapping ``[start, end)``, sorted by start."""
    icalendar_module: Any = need("icalendar", "caldav")
    recurring: Any = need("recurring_ical_events", "caldav")
    x_wr: Any = need("x_wr_timezone", "caldav")
    found: dict[str, Occurrence] = {}
    window_start, window_end = start.astimezone(zone), end.astimezone(zone)
    for text in texts:
        try:
            parsed = icalendar_module.Calendar.from_ical(text)
            parsed = x_wr.to_standard(parsed)
            instances = recurring.of(parsed, skip_bad_series=True).between(
                window_start, window_end,
            )
        except Exception as error:  # one broken object must not hide the others
            log.info("skipped an unreadable calendar object (%s)", type(error).__name__)
            continue
        for event in instances:
            try:
                item = _occurrence(event, zone, calendar, calendar_id)
            except (ValueError, TypeError, KeyError) as error:
                log.info("skipped an unreadable event (%s)", type(error).__name__)
                continue
            if item.end_at <= window_start or item.start_at >= window_end:
                continue
            found.setdefault(item.key, item)
            if len(found) >= MAX_OCCURRENCES:
                break
    return sorted(found.values(), key=lambda item: (item.start_at, item.title))


def _occurrence(
    event: icalendar.Event, zone: tzinfo, calendar: str, calendar_id: str,
) -> Occurrence:
    if str(event.get("STATUS", "")).upper() == "CANCELLED":
        raise ValueError("cancelled")
    start, all_day = _moment(event.decoded("DTSTART"), zone)
    if event.get("DTEND") is not None:
        end, _ = _moment(event.decoded("DTEND"), zone)
    elif event.get("DURATION") is not None:
        end = start + event.decoded("DURATION")
    else:
        end = start + (timedelta(days=1) if all_day else timedelta())
    if all_day:
        # Dates are wall-clock days: rebuild midnight in the zone (DST-safe).
        end = datetime.combine(end.date(), time(), tzinfo=zone)
    end = max(end, start)
    uid = str(event.get("UID", ""))
    identity = f"{calendar_id}\n{uid}\n{start.isoformat()}"
    key = "ev-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    return Occurrence(
        key=key,
        title=_text(event.get("SUMMARY")) or "(no title)",
        start=start.isoformat(),
        end=end.isoformat(),
        all_day=all_day,
        location=_text(event.get("LOCATION")),
        url=_link(event.get("URL")),
        calendar=_text(calendar),
    )
