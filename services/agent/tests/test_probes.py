"""RealProbes against fake DNS and fake sockets: address pinning, DNS policy, monitor method."""

from __future__ import annotations

import dataclasses
import socket
import threading

import httpx
import pytest
from bson import ObjectId

from app.config import settings
from app.security import ssrf
from app.store import InMemoryCollection
from app.tools.probes import RealProbes
from tests.agent_fakes import MONITOR_ID, make_alert

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def strict_settings(monkeypatch):
    monkeypatch.setattr(ssrf, "settings", dataclasses.replace(settings, allow_private_targets=False))


@pytest.fixture(autouse=True)
def no_system_dns(monkeypatch):
    """Any lookup that bypasses the injected resolver is a bug."""

    def refuse(*args, **kwargs):
        raise AssertionError("system resolver must not be used")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)


class RebindingResolver:
    """Answers public on the first lookup and loopback on every later one."""

    def __init__(self, first: str = PUBLIC_IP, later: str = "127.0.0.1") -> None:
        self.first, self.later = first, later
        self.calls = 0

    def __call__(self, host, port, *args, **kwargs):
        self.calls += 1
        addr = self.first if self.calls == 1 else self.later
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))]


def static_resolver(*addresses: str):
    def resolve(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    return resolve


def failing_resolver(host, port, *args, **kwargs):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def no_monitors_db() -> dict:
    return {"checkresults": InMemoryCollection()}


def monitors_db(**monitor) -> dict:
    doc = {"_id": ObjectId(MONITOR_ID), **monitor}
    return {"monitors": InMemoryCollection([doc]), "checkresults": InMemoryCollection()}


class RecordingConnect:
    """Stands in for socket.create_connection; records the address, then refuses."""

    def __init__(self) -> None:
        self.addresses: list[tuple] = []

    def __call__(self, address, *args, **kwargs):
        self.addresses.append(tuple(address))
        raise ConnectionRefusedError("refused by test")


# ── pinning ──────────────────────────────────────────────────────────────────


def test_probe_endpoint_connects_to_the_validated_address(monkeypatch):
    resolver = RebindingResolver()
    connect = RecordingConnect()
    monkeypatch.setattr(socket, "create_connection", connect)

    ev = RealProbes(no_monitors_db(), resolver=resolver).probe_endpoint(
        make_alert(monitorUrl="https://rebind.example/health")
    )

    assert resolver.calls == 1
    assert connect.addresses == [(PUBLIC_IP, 443)]
    assert ev.data["error"] == "ConnectError"


def test_check_tls_connects_to_the_validated_address(monkeypatch):
    resolver = RebindingResolver()
    connect = RecordingConnect()
    monkeypatch.setattr(socket, "create_connection", connect)

    ev = RealProbes(no_monitors_db(), resolver=resolver).check_tls(
        make_alert(monitorUrl="https://rebind.example:8443/")
    )

    assert resolver.calls == 1
    assert connect.addresses == [(PUBLIC_IP, 8443)]
    assert "TLS handshake failed" in ev.summary


def test_pinned_request_keeps_the_original_host_header(monkeypatch):
    """Route the pinned connection to a local listener and look at what arrives."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    received: list[bytes] = []

    def serve():
        conn, _ = server.accept()
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            received.append(data)
            conn.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n"
                b"Connection: close\r\n\r\ndown"
            )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    dialled: list[tuple] = []

    def redirect(address, timeout=None, *args, **kwargs):
        dialled.append(tuple(address))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(server.getsockname())
        return sock

    monkeypatch.setattr(socket, "create_connection", redirect)
    resolver = RebindingResolver()
    try:
        ev = RealProbes(no_monitors_db(), resolver=resolver).probe_endpoint(
            make_alert(monitorUrl="http://status.example:8080/health")
        )
    finally:
        thread.join(timeout=5)
        server.close()

    assert dialled == [(PUBLIC_IP, 8080)]
    assert resolver.calls == 1
    request = received[0].decode("latin-1").lower()
    assert request.startswith("get /health http/1.1")
    assert "host: status.example:8080" in request
    assert ev.data["status_code"] == 503


def test_probe_endpoint_hands_the_pinned_address_to_the_transport():
    seen: list[str] = []

    def factory(address: str) -> httpx.BaseTransport:
        seen.append(address)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    resolver = RebindingResolver()
    RealProbes(no_monitors_db(), resolver=resolver, transport_factory=factory).probe_endpoint(
        make_alert(monitorUrl="https://rebind.example/")
    )
    assert seen == [PUBLIC_IP]
    assert resolver.calls == 1


# ── DNS policy ───────────────────────────────────────────────────────────────


def test_check_dns_does_not_reveal_private_addresses():
    ev = RealProbes(no_monitors_db(), resolver=static_resolver("10.0.0.5")).check_dns(
        make_alert(monitorUrl="https://intranet.example/")
    )
    assert "10.0.0.5" not in ev.summary
    assert "10.0.0.5" not in repr(ev.data)
    assert "blocked by policy" in ev.summary
    assert ev.data == {"host": "intranet.example", "blocked": True}


def test_check_dns_blocks_internal_names_without_resolving():
    ev = RealProbes(no_monitors_db(), resolver=RebindingResolver()).check_dns(
        make_alert(monitorUrl="http://redis.internal:6379/")
    )
    assert ev.data["blocked"] is True


def test_check_dns_lists_public_addresses():
    ev = RealProbes(no_monitors_db(), resolver=static_resolver("93.184.216.35", PUBLIC_IP)).check_dns(
        make_alert(monitorUrl="https://example.com/")
    )
    assert ev.data["addresses"] == [PUBLIC_IP, "93.184.216.35"]
    assert PUBLIC_IP in ev.summary


def test_check_dns_failure_is_a_finding():
    ev = RealProbes(no_monitors_db(), resolver=failing_resolver).check_dns(
        make_alert(monitorUrl="https://gone.example/")
    )
    assert ev.summary.startswith("DNS resolution failed for gone.example")


@pytest.mark.parametrize("tool", ["probe_endpoint", "check_tls"])
def test_blocked_probes_do_not_reveal_private_addresses(tool):
    probes = RealProbes(no_monitors_db(), resolver=static_resolver(PUBLIC_IP, "10.0.0.5"))
    ev = getattr(probes, tool)(make_alert(monitorUrl="https://mixed.example/"))
    assert ev.data == {"blocked": True}
    assert "10.0.0.5" not in ev.summary


# ── monitor method and expected status ───────────────────────────────────────


def capture_transport(status: int, sink: list[httpx.Request]):
    def factory(address: str) -> httpx.BaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            sink.append(request)
            return httpx.Response(status, text="upstream says no")

        return httpx.MockTransport(handler)

    return factory


def test_probe_uses_monitor_method_and_expected_status():
    sent: list[httpx.Request] = []
    probes = RealProbes(
        monitors_db(method="post", expectedStatusCode=201, timeoutMs=2000),
        resolver=static_resolver(PUBLIC_IP),
        transport_factory=capture_transport(503, sent),
    )
    ev = probes.probe_endpoint(make_alert(monitorUrl="https://api.example/orders"))

    [request] = sent
    assert request.method == "POST"
    assert request.content == b""
    assert request.headers["host"] == "api.example"
    assert "expected 201, got 503" in ev.summary
    assert ev.data["method"] == "POST"
    assert ev.data["expected_status"] == 201
    assert ev.data["status_matches"] is False


def test_probe_reports_match_when_status_is_expected():
    sent: list[httpx.Request] = []
    probes = RealProbes(
        monitors_db(method="HEAD", expectedStatusCode=204),
        resolver=static_resolver(PUBLIC_IP),
        transport_factory=capture_transport(204, sent),
    )
    ev = probes.probe_endpoint(make_alert(monitorUrl="https://api.example/"))
    assert sent[0].method == "HEAD"
    assert "expected 204, got 204" in ev.summary
    assert ev.data["status_matches"] is True


def test_probe_defaults_without_monitors_collection():
    sent: list[httpx.Request] = []
    probes = RealProbes(
        no_monitors_db(),
        resolver=static_resolver(PUBLIC_IP),
        transport_factory=capture_transport(503, sent),
    )
    ev = probes.probe_endpoint(make_alert(monitorUrl="https://api.example/"))
    assert sent[0].method == "GET"
    assert "expected 200, got 503" in ev.summary


def test_probe_falls_back_to_get_for_unsupported_method():
    sent: list[httpx.Request] = []
    probes = RealProbes(
        monitors_db(method="CONNECT"),
        resolver=static_resolver(PUBLIC_IP),
        transport_factory=capture_transport(200, sent),
    )
    probes.probe_endpoint(make_alert(monitorUrl="https://api.example/"))
    assert sent[0].method == "GET"
