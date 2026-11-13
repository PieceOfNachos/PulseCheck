"""SSRF guard for every outbound request the agent makes on a monitor's behalf.

The monitored URL is user-supplied, so before probing it we make sure it points at
the public internet and not at our own network, the Docker bridge or a cloud
metadata endpoint.

DNS failures are *not* treated as blocked targets: an unresolvable host is a real
incident cause the agent has to diagnose, so ``socket.gaierror`` is re-raised as-is.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from app.config import settings

Resolver = Callable[..., Sequence[tuple[Any, ...]]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal", "metadata"})
BLOCKED_SUFFIXES = (".localhost", ".internal", ".local")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class BlockedTargetError(Exception):
    """The URL points somewhere the agent must never send requests."""


def is_blocked_ip(ip: IPAddress) -> bool:
    """True if ``ip`` is anything other than a plain public unicast address."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_blocked_ip(ip.ipv4_mapped)
        embedded = ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None and is_blocked_ip(embedded):
            return True
    if ip in METADATA_IPS:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    )


def _parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


def assert_public_url(url: str, resolver: Resolver | None = None) -> None:
    """Raise ``BlockedTargetError`` unless ``url`` is http(s) to a public host.

    Every address the hostname resolves to must be public, otherwise a DNS record
    with one public and one private A record could slip through. ``resolver`` has
    the ``socket.getaddrinfo`` signature and exists for tests.
    Re-raises ``socket.gaierror`` when the host does not resolve.
    """
    if settings.allow_private_targets:
        return

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise BlockedTargetError(f"malformed URL: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError(f"scheme {scheme or '(none)'!r} is not allowed")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise BlockedTargetError("URL has no host")

    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        raise BlockedTargetError(f"host {host!r} is internal")

    literal = _parse_ip(host)
    if literal is not None:
        if is_blocked_ip(literal):
            raise BlockedTargetError(f"address {literal} is not public")
        return

    resolve = resolver or socket.getaddrinfo
    infos = resolve(host, port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
    if not infos:
        raise socket.gaierror(f"no addresses for {host}")

    for info in infos:
        ip = _parse_ip(str(info[4][0]))
        if ip is None or is_blocked_ip(ip):
            raise BlockedTargetError(f"host {host!r} resolves to non-public address {info[4][0]}")
