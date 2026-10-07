"""Optional dependencies, imported on first use."""
from __future__ import annotations

import importlib
from types import ModuleType


class MissingExtraError(ImportError):
    """A feature needs a pip extra that is not installed."""

    def __init__(self, module: str, extra: str) -> None:
        super().__init__(
            f"{module} is not installed; install blueferry-plugin-kit[{extra}]", name=module,
        )
        self.extra = extra


def need(module: str, extra: str) -> ModuleType:
    """Import ``module`` or raise :class:`MissingExtraError` for ``extra``."""
    try:
        return importlib.import_module(module)
    except ImportError:
        raise MissingExtraError(module, extra) from None
