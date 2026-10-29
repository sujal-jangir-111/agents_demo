import logging
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import pytest


class FakeStorage:
    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}

    def get(self, key: str) -> Any:
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value


class FakeContext:
    """Stands in for uagents.Context so agent handlers can be called directly in pytest."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("fake-agent")
        self.storage = FakeStorage()
        self.agent = SimpleNamespace(address="agent1qfakeaddress")
        self.sent: List[Tuple[str, Any]] = []

    async def send(self, destination: str, message: Any) -> None:
        self.sent.append((destination, message))


@pytest.fixture
def ctx() -> FakeContext:
    return FakeContext()


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """uagents persists each agent's storage to `<address>_data.json` in the working directory. Run every test in
    a throwaway directory so tests never leak state into each other (or litter the project folder)."""
    monkeypatch.chdir(tmp_path)
