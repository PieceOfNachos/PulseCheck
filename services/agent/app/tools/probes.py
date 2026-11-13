"""Diagnostic tools the investigator can run against a monitor.

Tools take no arguments from the model: the target is always the monitor URL carried
by the alert, so the model can choose *which* check runs but never *where* it goes.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.contracts import AlertEvent, Evidence
from app.security.ssrf import BlockedTargetError, assert_public_url
from app.security.untrusted import wrap_untrusted
from app.store import to_object_id

TOOL_NAMES: list[str] = ["probe_endpoint", "check_dns", "check_tls", "recent_checks"]

TOOL_DESCRIPTIONS: dict[str, str] = {
    "probe_endpoint": "Send one GET request to the monitored URL (redirects are not followed) "
    "and report status code, latency, key headers and a truncated body.",
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


class Probes(Protocol):
    def probe_endpoint(self, alert: AlertEvent) -> Evidence: ...
    def check_dns(self, alert: AlertEvent) -> Evidence: ...
    def check_tls(self, alert: AlertEvent) -> Evidence: ...
    def recent_checks(self, alert: AlertEvent) -> Evidence: ...


class RealProbes:
    """Network and database backed probes. ``db`` maps collection names to collections."""

    def __init__(self, db: Any, default_timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.db = db
        self.default_timeout = default_timeout

    def _timeout(self, alert: AlertEvent) -> float:
        """The monitor's own timeout, capped, falling back to the default."""
        try:
            oid = to_object_id(alert.monitorId)
            monitor = self.db["monitors"].find_one({"_id": oid}) if oid else None
            ms = (monitor or {}).get("timeoutMs")
            if ms:
                return min(float(ms) / 1000, MAX_TIMEOUT_S)
        except Exception:
            pass
        return self.default_timeout

    def probe_endpoint(self, alert: AlertEvent) -> Evidence:
        url = alert.monitorUrl
        try:
            assert_public_url(url)
        except BlockedTargetError as exc:
            return Evidence(
                tool="probe_endpoint",
                summary=f"Blocked by SSRF policy, request not sent: {exc}.",
                data={"blocked": True, "reason": str(exc)},
            )
        except socket.gaierror as exc:
            return Evidence(
                tool="probe_endpoint",
                summary=f"DNS resolution failed, request not sent: {exc}.",
                data={"error": "dns", "detail": str(exc)},
            )

        timeout = self._timeout(alert)
        start = time.perf_counter()
        try:
            with httpx.Client(follow_redirects=False, timeout=timeout) as client:
                with client.stream("GET", url, headers={"User-Agent": "PulseCheck-Agent/1.0"}) as r:
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
                summary=f"Request timed out after {timeout:g}s.",
                data={"error": "timeout", "timeout_s": timeout},
            )
        except httpx.HTTPError as exc:
            return Evidence(
                tool="probe_endpoint",
                summary=f"Request failed: {type(exc).__name__}: {exc}",
                data={"error": type(exc).__name__, "detail": str(exc)},
            )

        body = wrap_untrusted(raw.decode("utf-8", errors="replace"), source="probe_endpoint")
        summary = f"HTTP {status} {reason} in {latency} ms"
        if "server" in headers:
            summary += f", server: {headers['server']}"
        if "location" in headers:
            summary += f", redirects to {headers['location']} (not followed)"
        return Evidence(
            tool="probe_endpoint",
            summary=f"{summary}, body: {body}",
            data={"status_code": status, "latency_ms": latency, "headers": headers},
        )

    def check_dns(self, alert: AlertEvent) -> Evidence:
        host = urlsplit(alert.monitorUrl).hostname
        if not host:
            return Evidence(tool="check_dns", summary="Monitor URL has no host name.")
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            return Evidence(
                tool="check_dns",
                summary=f"DNS resolution failed for {host}: {exc}",
                data={"host": host, "error": str(exc)},
            )
        addresses = sorted({str(info[4][0]) for info in infos})
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
            assert_public_url(alert.monitorUrl)
        except BlockedTargetError as exc:
            return Evidence(
                tool="check_tls",
                summary=f"Blocked by SSRF policy, connection not opened: {exc}.",
                data={"blocked": True, "reason": str(exc)},
            )
        except socket.gaierror as exc:
            return Evidence(tool="check_tls", summary=f"Host did not resolve ({exc}).")

        host, port = parts.hostname, parts.port or 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT_S) as sock:
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
