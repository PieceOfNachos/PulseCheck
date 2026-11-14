"""Diagnostic tools the investigator can run against a monitor.

Tools take no arguments from the model: the target is always the monitor URL carried
by the alert, so the model can choose *which* check runs but never *where* it goes.

Network probes resolve the host once through the SSRF guard and then connect to that
validated address, never to the host name, so DNS cannot change the answer between
the check and the connection.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

import httpcore
import httpx

from app.contracts import AlertEvent, Evidence
from app.security.ssrf import BlockedTargetError, Resolver, resolve_public
from app.security.untrusted import wrap_untrusted
from app.store import to_object_id

TOOL_NAMES: list[str] = ["probe_endpoint", "check_dns", "check_tls", "recent_checks"]

TOOL_DESCRIPTIONS: dict[str, str] = {
    "probe_endpoint": "Send one request to the monitored URL with the monitor's own HTTP method "
    "(redirects are not followed) and report the status code against the expected one, "
    "latency, key headers and a truncated body.",
    "check_dns": "Resolve the monitored host name and list the addresses it resolves to.",
    "check_tls": "Open a TLS connection to the monitored host and report certificate validity, "
    "expiry date, days left and issuer, or the TLS error.",
    "recent_checks": "Summarise the last 20 recorded checks for this monitor: DOWN ratio, "
    "average latency and distinct errors.",
}

DEFAULT_TIMEOUT_S = 5.0
MAX_TIMEOUT_S = 15.0
BODY_READ_BYTES = 16_384
HEADER_SUBSET = ("server", "content-type", "location")
USER_AGENT = "PulseCheck-Agent/1.0"
DEFAULT_METHOD = "GET"
DEFAULT_EXPECTED_STATUS = 200
# The monitor schema also allows CONNECT, which makes no sense as a one-off probe.
PROBE_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"})
BLOCKED_DETAIL = "target is not a public http(s) address"

TransportFactory = Callable[[str], httpx.BaseTransport]


class Probes(Protocol):
    def probe_endpoint(self, alert: AlertEvent) -> Evidence: ...
    def check_dns(self, alert: AlertEvent) -> Evidence: ...
    def check_tls(self, alert: AlertEvent) -> Evidence: ...
    def recent_checks(self, alert: AlertEvent) -> Evidence: ...


class PinnedBackend(httpcore.NetworkBackend):
    """Dials one fixed, already validated address whatever host the request names.

    httpcore keeps using the URL's host name for the ``Host`` header, TLS SNI and
    certificate verification; only the TCP destination changes.
    """

    def __init__(self, address: str, inner: httpcore.NetworkBackend | None = None) -> None:
        self.address = address
        self._inner = inner or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        return self._inner.connect_tcp(
            self.address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def pinned_transport(address: str) -> httpx.BaseTransport:
    """An httpx transport whose every connection goes to ``address``.

    httpx has no public hook for the network backend, so this replaces it on the
    transport's connection pool. Connections pick the backend up from the pool when
    they are created, so swapping it before the first request is enough.
    """
    transport = httpx.HTTPTransport(retries=0)
    pool = getattr(transport, "_pool", None)
    if not isinstance(pool, httpcore.ConnectionPool) or not hasattr(pool, "_network_backend"):
        raise RuntimeError("unsupported httpx/httpcore version: cannot pin the target address")
    pool._network_backend = PinnedBackend(address)
    return transport


def _blocked(tool: str, what: str) -> Evidence:
    # The guard's own message names the internal address; keep it out of the evidence.
    return Evidence(
        tool=tool,
        summary=f"Blocked by SSRF policy, {what}: {BLOCKED_DETAIL}.",
        data={"blocked": True},
    )


class RealProbes:
    """Network and database backed probes. ``db`` maps collection names to collections.

    ``resolver`` (``socket.getaddrinfo`` signature) and ``transport_factory`` exist so
    tests can run without touching the network.
    """

    def __init__(
        self,
        db: Any,
        default_timeout: float = DEFAULT_TIMEOUT_S,
        resolver: Resolver | None = None,
        transport_factory: TransportFactory = pinned_transport,
    ) -> None:
        self.db = db
        self.default_timeout = default_timeout
        self.resolver = resolver
        self.transport_factory = transport_factory

    def _monitor(self, alert: AlertEvent) -> dict[str, Any]:
        """The monitor document, or ``{}`` when it is missing or unreadable."""
        try:
            oid = to_object_id(alert.monitorId)
            return (self.db["monitors"].find_one({"_id": oid}) if oid else None) or {}
        except Exception:
            return {}

    def _timeout(self, monitor: dict[str, Any]) -> float:
        """The monitor's own timeout, capped, falling back to the default."""
        try:
            ms = monitor.get("timeoutMs")
            if ms:
                return min(float(ms) / 1000, MAX_TIMEOUT_S)
        except (TypeError, ValueError):
            pass
        return self.default_timeout

    @staticmethod
    def _method(monitor: dict[str, Any]) -> str:
        method = str(monitor.get("method") or DEFAULT_METHOD).strip().upper()
        return method if method in PROBE_METHODS else DEFAULT_METHOD

    @staticmethod
    def _expected_status(monitor: dict[str, Any]) -> int:
        try:
            return int(monitor.get("expectedStatusCode") or DEFAULT_EXPECTED_STATUS)
        except (TypeError, ValueError):
            return DEFAULT_EXPECTED_STATUS

    def probe_endpoint(self, alert: AlertEvent) -> Evidence:
        url = alert.monitorUrl
        try:
            _, _, addresses = resolve_public(url, self.resolver)
        except BlockedTargetError:
            return _blocked("probe_endpoint", "request not sent")
        except socket.gaierror as exc:
            return Evidence(
                tool="probe_endpoint",
                summary=f"DNS resolution failed, request not sent: {exc}.",
                data={"error": "dns", "detail": str(exc)},
            )

        monitor = self._monitor(alert)
        timeout = self._timeout(monitor)
        method = self._method(monitor)
        expected = self._expected_status(monitor)
        start = time.perf_counter()
        try:
            with httpx.Client(
                transport=self.transport_factory(addresses[0]),
                follow_redirects=False,
                timeout=timeout,
                trust_env=False,
            ) as client:
                with client.stream(method, url, headers={"User-Agent": USER_AGENT}) as r:
                    raw = b""
                    for chunk in r.iter_bytes():
                        raw += chunk
                        if len(raw) >= BODY_READ_BYTES:
                            break
                    latency = round((time.perf_counter() - start) * 1000)
                    headers = {h: r.headers[h] for h in HEADER_SUBSET if h in r.headers}
                    status, reason = r.status_code, r.reason_phrase
        except httpx.TimeoutException:
            return Evidence(
                tool="probe_endpoint",
                summary=f"{method} request timed out after {timeout:g}s.",
                data={"error": "timeout", "timeout_s": timeout, "method": method},
            )
        except httpx.HTTPError as exc:
            return Evidence(
                tool="probe_endpoint",
                summary=f"{method} request failed: {type(exc).__name__}: {exc}",
                data={"error": type(exc).__name__, "detail": str(exc), "method": method},
            )

        body = wrap_untrusted(raw.decode("utf-8", errors="replace"), source="probe_endpoint")
        summary = (
            f"{method} returned HTTP {status} {reason} in {latency} ms "
            f"(expected {expected}, got {status})"
        )
        if "server" in headers:
            summary += f", server: {headers['server']}"
        if "location" in headers:
            summary += f", redirects to {headers['location']} (not followed)"
        return Evidence(
            tool="probe_endpoint",
            summary=f"{summary}, body: {body}",
            data={
                "method": method,
                "status_code": status,
                "expected_status": expected,
                "status_matches": status == expected,
                "latency_ms": latency,
                "headers": headers,
            },
        )

    def check_dns(self, alert: AlertEvent) -> Evidence:
        host = urlsplit(alert.monitorUrl).hostname
        if not host:
            return Evidence(tool="check_dns", summary="Monitor URL has no host name.")
        try:
            _, _, addresses = resolve_public(alert.monitorUrl, self.resolver)
        except socket.gaierror as exc:
            return Evidence(
                tool="check_dns",
                summary=f"DNS resolution failed for {host}: {exc}",
                data={"host": host, "error": str(exc)},
            )
        except BlockedTargetError:
            return Evidence(
                tool="check_dns",
                summary=f"{host} is internal or resolves to a non-public address; "
                "blocked by policy, addresses not shown.",
                data={"host": host, "blocked": True},
            )
        addresses = sorted(addresses)
        return Evidence(
            tool="check_dns",
            summary=f"{host} resolves to {', '.join(addresses)}",
            data={"host": host, "addresses": addresses},
        )

    def check_tls(self, alert: AlertEvent) -> Evidence:
        parts = urlsplit(alert.monitorUrl)
        if parts.scheme != "https" or not parts.hostname:
            return Evidence(tool="check_tls", summary="Skipped: monitor URL is not https.")
        try:
            host, port, addresses = resolve_public(alert.monitorUrl, self.resolver)
        except BlockedTargetError:
            return _blocked("check_tls", "connection not opened")
        except socket.gaierror as exc:
            return Evidence(tool="check_tls", summary=f"Host did not resolve ({exc}).")

        context = ssl.create_default_context()
        try:
            with socket.create_connection((addresses[0], port), timeout=DEFAULT_TIMEOUT_S) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            return Evidence(
                tool="check_tls",
                summary=f"TLS certificate verification failed: {exc.verify_message or exc}",
                data={"error": "verification", "detail": str(exc)},
            )
        except (ssl.SSLError, OSError) as exc:
            return Evidence(
                tool="check_tls",
                summary=f"TLS handshake failed: {type(exc).__name__}: {exc}",
                data={"error": type(exc).__name__, "detail": str(exc)},
            )

        not_after = str(cert.get("notAfter", ""))
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        issuer_name = issuer.get("organizationName") or issuer.get("commonName", "unknown")
        return Evidence(
            tool="check_tls",
            summary=f"Certificate valid, expires {expires:%Y-%m-%d} ({days_left} days left), "
            f"issuer: {issuer_name}",
            data={"not_after": expires.isoformat(), "days_left": days_left, "issuer": issuer_name},
        )

    def recent_checks(self, alert: AlertEvent) -> Evidence:
        oid = to_object_id(alert.monitorId)
        if oid is None:
            return Evidence(tool="recent_checks", summary="Invalid monitor id; no history.")
        docs = list(
            self.db["checkresults"].find({"monitorId": oid}, sort=[("checkedAt", -1)], limit=20)
        )
        if not docs:
            return Evidence(tool="recent_checks", summary="No recorded checks for this monitor.")

        down = sum(1 for d in docs if d.get("status") == "DOWN")
        latencies = [d["latencyMs"] for d in docs if isinstance(d.get("latencyMs"), (int, float))]
        avg = round(sum(latencies) / len(latencies)) if latencies else None
        errors = Counter(str(d["errorMessage"]) for d in docs if d.get("errorMessage"))
        summary = f"{down}/{len(docs)} recent checks DOWN, avg latency {avg} ms"
        if errors:
            summary += "; errors: " + ", ".join(f"{e} (x{n})" for e, n in errors.most_common(5))
        return Evidence(
            tool="recent_checks",
            summary=summary,
            data={
                "checks": len(docs),
                "down": down,
                "avg_latency_ms": avg,
                "errors": dict(errors.most_common(5)),
            },
        )
