"""Keep tests away from the user's configuration, keyring, bus and display."""
from __future__ import annotations

from blueferry_plugin_kit.testing import isolate_environment

isolate_environment("blueferry-plugin-kit-tests-")
