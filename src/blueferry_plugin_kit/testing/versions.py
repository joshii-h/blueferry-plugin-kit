"""One version everywhere: manifest ``Version=``, pyproject and ``__version__``.

``blueferry plugins list`` shows the manifest's version, pip the
pyproject's, the plugin's ``GetInfo`` its ``__version__``. A release that
bumps only some of them confuses everybody, so every plugin keeps a test::

    from pathlib import Path
    from blueferry_plugin_kit.testing import check_versions
    from blueferry_myplugin import __version__

    def test_versions_match():
        check_versions(Path(__file__).parent.parent, __version__)
"""
from __future__ import annotations

import re
from pathlib import Path

_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_PROJECT_VERSION = re.compile(r'^\s*version\s*=\s*"([^"]+)"\s*$')


def _manifest_version(path: Path) -> str | None:
    section = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _SECTION.match(line)
        if match:
            section = match.group(1)
        elif section == "BlueFerry Plugin" and line.startswith("Version="):
            return line.split("=", 1)[1].strip()
    return None


def _pyproject_version(path: Path) -> str | None:
    section = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _SECTION.match(line)
        if match:
            section = match.group(1).strip()
            continue
        if section == "project":
            found = _PROJECT_VERSION.match(line)
            if found:
                return found.group(1)
    return None


def manifests(root: Path) -> list[Path]:
    """The plugin's ``*.plugin`` files below ``src/`` and ``data/``."""
    found: list[Path] = []
    for folder in ("src", "data"):
        if (root / folder).is_dir():
            found.extend(sorted((root / folder).rglob("*.plugin")))
    return found


def check_versions(root: Path, package_version: str) -> str:
    """Assert that manifest, pyproject and ``package_version`` agree.

    ``root`` is the repository (the directory with ``pyproject.toml``).
    Returns the version.
    """
    found = manifests(root)
    if len(found) != 1:
        raise AssertionError(f"expected exactly one manifest, found {len(found)}")
    versions = {
        f"manifest {found[0].name}": _manifest_version(found[0]),
        "pyproject.toml": _pyproject_version(root / "pyproject.toml"),
        "__version__": package_version,
    }
    if len(set(versions.values())) != 1 or None in versions.values():
        listed = ", ".join(f"{where}: {version}" for where, version in versions.items())
        raise AssertionError(f"versions differ: {listed}")
    return package_version
