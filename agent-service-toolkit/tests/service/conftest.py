from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from service import app


@pytest.fixture(autouse=True)
def neutralize_ambient_auth_secret(monkeypatch):
    """Neutralize any ambient AUTH_SECRET for the service tests.

    When this toolkit is absorbed into the parent repo, `core.settings` resolves
    its env file via `find_dotenv()`, which walks up past the toolkit (no local
    `.env`) to the repo-root `.env`. That real `AUTH_SECRET` would enable FastAPI
    bearer auth and 401 the unauthenticated tests here that exercise the mocked
    agent through the real `test_client`. We null it at import scope for these
    tests only — source and the root `.env` are left untouched so authenticated
    runs still work. Auth-specific tests use the `mock_settings` fixture, which
    replaces `service.service.settings` wholesale and is therefore unaffected.
    """
    monkeypatch.setattr("service.service.settings.AUTH_SECRET", None)


@pytest.fixture
def test_client():
    """Fixture to create a FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mock_agent():
    """Fixture to create a mock agent that can be configured for different test scenarios."""
    agent_mock = AsyncMock()
    agent_mock.ainvoke = AsyncMock(
        return_value=[("values", {"messages": [AIMessage(content="Test response")]})]
    )
    agent_mock.get_state = Mock()  # Default empty mock for get_state
    with patch("service.service.get_agent", Mock(return_value=agent_mock)):
        yield agent_mock


@pytest.fixture
def mock_settings(mock_env):
    """Fixture to ensure settings are clean for each test."""
    with patch("service.service.settings") as mock_settings:
        yield mock_settings


@pytest.fixture
def mock_httpx():
    """Patch httpx.stream and httpx.get to use our test client."""

    with TestClient(app) as client:

        def mock_stream(method: str, url: str, **kwargs):
            # Strip the base URL since TestClient expects just the path
            path = url.replace("http://0.0.0.0", "")
            return client.stream(method, path, **kwargs)

        def mock_get(url: str, **kwargs):
            # Strip the base URL since TestClient expects just the path
            path = url.replace("http://0.0.0.0", "")
            return client.get(path, **kwargs)

        with patch("httpx.stream", mock_stream):
            with patch("httpx.get", mock_get):
                yield
