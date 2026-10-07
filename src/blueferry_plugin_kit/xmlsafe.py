"""Parse XML from a server without DTDs, entities or external references.

A thin wrapper over defusedxml (extra ``xml``, also part of ``dav`` and
``caldav``): any DOCTYPE is refused wherever it appears in the document,
not only in the first bytes, so neither entity expansion ("billion laughs")
nor external entities can happen. Errors are one exception type,
:class:`XmlError`, whose message names no content.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET  # nosec B405 - only for types; parsing uses defusedxml

from blueferry_plugin_kit._extras import need

__all__ = ["Element", "XmlError", "fromstring"]

Element = ET.Element


class XmlError(ValueError):
    """Not well-formed, too large or forbidden (DTD, entities)."""


def fromstring(data: bytes | str, *, limit: int | None = None) -> ET.Element:
    """The root element of ``data``; raise :class:`XmlError` otherwise.

    ``limit`` caps the input size in bytes (characters for ``str``).
    """
    if limit is not None and len(data) > limit:
        raise XmlError("too large")
    safe = need("defusedxml.ElementTree", "xml")
    common = need("defusedxml.common", "xml")
    try:
        return safe.fromstring(data, forbid_dtd=True)
    except (ET.ParseError, common.DefusedXmlException):
        raise XmlError("not well-formed or forbidden") from None
