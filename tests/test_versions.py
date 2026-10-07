from __future__ import annotations

from pathlib import Path

import pytest

import blueferry_plugin_kit
from blueferry_plugin_kit.testing import check_versions

ROOT = Path(__file__).resolve().parent.parent


def _repo(tmp_path: Path, manifest: str, project: str) -> Path:
    (tmp_path / "src" / "pkg").mkdir(parents=True)
    (tmp_path / "src" / "pkg" / "io.example.x.plugin").write_text(
        f"[BlueFerry Plugin]\nId=io.example.x\nVersion={manifest}\n\n[Config a]\nVersion=9\n",
    )
    (tmp_path / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["x"]\n\n[project]\nname = "x"\nversion = "{project}"\n'
        '\n[tool.other]\nversion = "7"\n',
    )
    return tmp_path


def test_matching_versions(tmp_path) -> None:
    assert check_versions(_repo(tmp_path, "0.2.0", "0.2.0"), "0.2.0") == "0.2.0"


@pytest.mark.parametrize(("manifest", "project", "package"), [
    ("0.1.1", "0.1.2", "0.1.2"), ("0.1.2", "0.1.2", "0.1.1"), ("0.1.2", "0.1.1", "0.1.2"),
])
def test_differing_versions(tmp_path, manifest, project, package) -> None:
    with pytest.raises(AssertionError, match="versions differ"):
        check_versions(_repo(tmp_path, manifest, project), package)


def test_needs_one_manifest(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1"\n')
    with pytest.raises(AssertionError, match="exactly one manifest"):
        check_versions(tmp_path, "1")


def test_kit_version_matches_pyproject() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{blueferry_plugin_kit.__version__}"' in text
