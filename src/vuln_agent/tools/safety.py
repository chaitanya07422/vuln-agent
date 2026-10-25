from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse


def is_blocked_hostname(host: Optional[str]) -> bool:
    if not host:
        return True
    h = host.lower().strip(".")
    if h in {"localhost", "metadata.google.internal"} or h.endswith(".local") or h.endswith(".internal"):
        return True
    if h.endswith(".localhost"):
        return True
    return False


def is_private_or_local_ip(ip_str: str) -> bool:
    """True if ip_str is a private/local IP. Raises ValueError if not an IP."""
    ip = ipaddress.ip_address(ip_str)
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or not ip.is_global
    )


def _host_in_allowlist(host: str, allow_hosts: List[str]) -> bool:
    for allowed in allow_hosts:
        a = allowed.lower()
        if host == a or host.endswith("." + a):
            return True
    return False


def resolve_public_ips(host: str) -> Optional[List[str]]:
    """Return public IPs, [] if only private, None if DNS failed."""
    if is_blocked_hostname(host):
        return []
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    public: List[str] = []
    saw_any = False
    for info in infos:
        saw_any = True
        addr = info[4][0]
        try:
            private = is_private_or_local_ip(addr)
        except ValueError:
            continue
        if not private and addr not in public:
            public.append(addr)
    if not saw_any:
        return None
    return public


def url_is_safe_target(url: str, allow_hosts: Optional[List[str]] = None) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if is_blocked_hostname(host):
        return False

    # Literal IP in hostname
    try:
        if is_private_or_local_ip(host):
            return False
        if allow_hosts is not None and not _host_in_allowlist(host, allow_hosts):
            return False
        return True
    except ValueError:
        pass  # hostname, not an IP

    if allow_hosts is not None and not _host_in_allowlist(host, allow_hosts):
        return False

    ips = resolve_public_ips(host)
    if ips is None:
        # DNS unavailable — allow allowlisted hostnames only
        return allow_hosts is not None and _host_in_allowlist(host, allow_hosts)
    return bool(ips)
