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


def resolve_public(url: str, resolver: Resolver | None = None) -> tuple[str, int, list[str]]:
    """Resolve ``url`` once and return ``(host, port, addresses)`` that passed the policy.

    Callers must connect to one of the returned addresses rather than the hostname:
    resolving again at connect time would let a zero-TTL record answer public here
    and private for the real connection (DNS rebinding).

    Every address the hostname resolves to must be public, otherwise a DNS record
    with one public and one private A record could slip through. ``resolver`` has
    the ``socket.getaddrinfo`` signature and exists for tests.
    Re-raises ``socket.gaierror`` when the host does not resolve.

    With ``AGENT_ALLOW_PRIVATE_TARGETS`` the address policy is skipped, but the URL
    is still parsed and resolved so callers can pin the connection the same way.
    """
    enforce = not settings.allow_private_targets
    try:
        parts = urlsplit(url)
        explicit_port = parts.port
    except ValueError as exc:
        raise BlockedTargetError(f"malformed URL: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError(f"scheme {scheme or '(none)'!r} is not allowed")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise BlockedTargetError("URL has no host")
    port = explicit_port or (443 if scheme == "https" else 80)

    if enforce and (host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES)):
        raise BlockedTargetError(f"host {host!r} is internal")

    literal = _parse_ip(host)
    if literal is not None:
        if enforce and is_blocked_ip(literal):
            raise BlockedTargetError(f"address {literal} is not public")
        return host, port, [str(literal)]

    resolve = resolver or socket.getaddrinfo
    infos = resolve(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise socket.gaierror(f"no addresses for {host}")

    addresses: list[str] = []
    for info in infos:
        raw = str(info[4][0])
        ip = _parse_ip(raw)
        if ip is None:
            raise BlockedTargetError(f"host {host!r} resolves to unparseable address {raw}")
        if enforce and is_blocked_ip(ip):
            raise BlockedTargetError(f"host {host!r} resolves to non-public address {raw}")
        if str(ip) not in addresses:
            addresses.append(str(ip))
    return host, port, addresses


def assert_public_url(url: str, resolver: Resolver | None = None) -> None:
    """Raise ``BlockedTargetError`` unless ``url`` is http(s) to a public host.

    A yes/no check only. Anything that goes on to open a connection should use
    ``resolve_public`` and connect to the address it returns.
    """
    if settings.allow_private_targets:
        return
    resolve_public(url, resolver)
