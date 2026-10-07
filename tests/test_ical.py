"""Recurrence expansion, time zones and untrusted event text."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from blueferry_plugin_kit.dav.ical import Occurrence, occurrences

ICS = Path(__file__).parent / "fixtures" / "ics"
ZURICH = ZoneInfo("Europe/Zurich")
START = datetime(2026, 10, 6, tzinfo=ZURICH)
END = datetime(2026, 10, 8, tzinfo=ZURICH)


def _load(*names: str) -> list[str]:
    return [(ICS / name).read_text() for name in names]


def _summary(events: list[Occurrence]) -> list[tuple[str, str]]:
    return [(e.title, e.start_at.astimezone(ZURICH).strftime("%d %H:%M")) for e in events]


def test_recurring_event_with_override_and_exdate() -> None:
    events = occurrences(_load("standup.ics"), START, END, ZURICH)
    # Tuesday's instance moved to 10:00, Wednesday's is excluded.
    assert _summary(events) == [("Team standup (moved)", "06 10:00")]
    assert events[0].location == "Room 4"
    assert events[0].end_at.astimezone(ZURICH).strftime("%H:%M") == "10:15"


def test_time_zones_floating_and_all_day() -> None:
    events = occurrences(
        _load("call.ics", "dinner.ics", "birthday.ics", "newyork.ics"), START, END, ZURICH,
    )
    assert _summary(events) == [
        ("Call with New York", "06 17:00"),   # 15:00Z
        ("Dinner", "06 19:00"),               # floating: local time
        ("Anna's birthday", "07 00:00"),      # yearly all-day
        ("Design review", "07 15:00"),        # 09:00 America/New_York, DURATION
    ]
    birthday = events[2]
    assert birthday.all_day and birthday.end_at == datetime(2026, 10, 8, tzinfo=ZURICH)
    assert "Cancelled meeting" not in [e.title for e in events]


def test_only_http_links_survive() -> None:
    events = occurrences(_load("call.ics", "dinner.ics"), START, END, ZURICH)
    by_title = {e.title: e for e in events}
    assert by_title["Call with New York"].url == "https://meet.example.org/abc-def"
    assert by_title["Dinner"].url == ""          # javascript: dropped
    assert by_title["Dinner"].location == "Zum Löwen, Bern"


def test_dst_change_keeps_local_wall_time() -> None:
    text = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:daily\r\n"
        "DTSTAMP:20261001T000000Z\r\nDTSTART;TZID=Europe/Zurich:20261020T090000\r\n"
        "DURATION:PT1H\r\nRRULE:FREQ=DAILY\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    events = occurrences([text], datetime(2026, 10, 24, tzinfo=ZURICH),
                         datetime(2026, 10, 27, tzinfo=ZURICH), ZURICH)
    assert [e.start_at.strftime("%d %H:%M %z") for e in events] == [
        "24 09:00 +0200", "25 09:00 +0100", "26 09:00 +0100",
    ]


def test_broken_objects_are_skipped_and_keys_are_stable() -> None:
    texts = ["not a calendar", *_load("call.ics")]
    first = occurrences(texts, START, END, ZURICH, calendar_id="a")
    second = occurrences(texts, START, END, ZURICH, calendar_id="a")
    other = occurrences(texts, START, END, ZURICH, calendar_id="b")
    assert len(first) == 1 and first[0].key == second[0].key != other[0].key
    assert first[0].key.startswith("ev-") and "New York" not in first[0].key


def test_control_characters_and_long_titles_are_cleaned() -> None:
    text = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:x\r\n"
        "DTSTAMP:20261001T000000Z\r\nDTSTART:20261006T120000Z\r\nDTEND:20261006T130000Z\r\n"
        "SUMMARY:Evil\\n\x1b[31mtitle " + "x" * 400 + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    [event] = occurrences([text], START, END, ZURICH)
    assert "\x1b" not in event.title and "\n" not in event.title and len(event.title) <= 200


def test_occurrence_json_round_trip() -> None:
    [event] = occurrences(_load("call.ics"), START, END, ZURICH)
    assert Occurrence.from_json(event.to_json()) == event
    assert Occurrence.from_json({"key": "x"}) is None
    assert Occurrence.from_json({**event.to_json(), "start": "2026-10-06T10:00"}) is None
