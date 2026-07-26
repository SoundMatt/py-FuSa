"""Rule base class and registry helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyfusa
    from pyfusa.config import Config


class Rule(ABC):
    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]: ...
