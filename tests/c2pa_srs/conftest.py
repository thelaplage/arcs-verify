"""Every test in this package runs with the network closed.

The tripwire records an attempt and raises. It also asserts at teardown that no attempt
was recorded, so an adapter that caught and swallowed the exception still fails the test.
"""
import socket

import pytest


@pytest.fixture(autouse=True)
def no_ambient_validator(monkeypatch):
    """The verifier never falls back to an ambient executable; tests pass one explicitly."""
    monkeypatch.delenv("ARCS_VERIFY_C2PATOOL", raising=False)


@pytest.fixture(autouse=True)
def network_tripwire(monkeypatch):
    attempts: list[tuple] = []

    def deny(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError("network use is forbidden in offline adapter tests")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, deny)
    yield attempts
    assert attempts == [], f"network attempted: {len(attempts)} call(s)"
