"""Shared building blocks for BlueFerry plugins.

The core modules (:mod:`~blueferry_plugin_kit.secrets`,
:mod:`~blueferry_plugin_kit.clipboard`, :mod:`~blueferry_plugin_kit.netaddr`,
:mod:`~blueferry_plugin_kit.xmlsafe`, :mod:`~blueferry_plugin_kit.auth` and
:mod:`~blueferry_plugin_kit.testing`) import nothing beyond the standard
library and the plugin contract. :mod:`~blueferry_plugin_kit.lanserver` and
:mod:`~blueferry_plugin_kit.dav` import fine too, but the parts that need a
third-party library load it on first use and raise :class:`MissingExtraError`
naming the pip extra when it is not installed.
"""
from __future__ import annotations

from blueferry_plugin_kit._extras import MissingExtraError

__version__ = "0.2.0"
__all__ = ["MissingExtraError", "__version__"]
