from __future__ import annotations

import pytest

from blueferry_plugin_kit import xmlsafe


def test_parses_namespaced_xml() -> None:
    root = xmlsafe.fromstring(b'<d:multistatus xmlns:d="DAV:"><d:response/></d:multistatus>')
    assert root.tag == "{DAV:}multistatus" and len(root) == 1


@pytest.mark.parametrize("data", [
    b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>',
    b'<!DOCTYPE x SYSTEM "http://evil.example/x.dtd"><x/>',
    # Past the first kilobytes, too.
    b"<?xml version='1.0'?><!--" + b"x" * 8192 + b'--><!DOCTYPE x [<!ENTITY a "b">]><x/>',
    b"<x>",
    b"",
])
def test_doctypes_entities_and_garbage_are_refused(data) -> None:
    with pytest.raises(xmlsafe.XmlError):
        xmlsafe.fromstring(data)


def test_size_limit() -> None:
    with pytest.raises(xmlsafe.XmlError, match="too large"):
        xmlsafe.fromstring(b"<x>" + b"a" * 100 + b"</x>", limit=50)
    assert xmlsafe.fromstring(b"<x/>", limit=50).tag == "x"
