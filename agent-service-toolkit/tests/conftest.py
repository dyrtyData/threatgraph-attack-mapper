import os
from unittest.mock import patch

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-docker", action="store_true", default=False, help="run docker integration tests"
    )
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="run integration tests requiring heavy model downloads / network",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: mark test as requiring docker containers")
    config.addinivalue_line(
        "markers",
        "integration: mark test as requiring a heavy model download / network (opt-in)",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-docker"):
        skip_docker = pytest.mark.skip(reason="need --run-docker option to run")
        for item in items:
            if "docker" in item.keywords:
                item.add_marker(skip_docker)
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


@pytest.fixture
def mock_env():
    """Fixture to ensure environment is clean for each test."""
    with patch.dict(os.environ, {}, clear=True):
        yield


@pytest.fixture(autouse=True)
def _mem0_offline_by_default(monkeypatch):
    """Keep the default suite OFFLINE: disable hosted Mem0 unless a test opts in.

    The repo-root ``.env`` carries a real ``MEM0_API_KEY`` (picked up by ``find_dotenv`` when
    ``Settings`` is constructed), which would otherwise make the ``threatgraph`` extractor /
    defensive_guardrail issue real Mem0 network calls during tests. Neutralize it globally
    (test-scoped, auto-reverted) and clear the cached client. Tests that exercise the enabled
    path re-set the key via their own ``monkeypatch`` — that runs after this fixture and wins,
    and injects a fake ``MemoryClient`` so no real network call ever happens. Mirrors the
    Phase-0 ``AUTH_SECRET`` neutralization pattern.
    """
    try:
        from core.settings import settings as _settings

        monkeypatch.setattr(_settings, "MEM0_API_KEY", None, raising=False)
        from memory.mem0_client import get_mem0

        get_mem0.cache_clear()
        yield
        get_mem0.cache_clear()
    except Exception:
        # If the toolkit modules aren't importable in some test context, don't block the test.
        yield
