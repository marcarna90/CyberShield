"""Authorised scanning scope enforcement.

Every active network operation goes through :class:`TargetScope`. Targets must
fall inside the operator-defined allow-list (``CYBERSHIELD_ALLOWED_TARGETS``,
private ranges by default). Hostnames are resolved **once** here and the
resolved IP is what gets scanned, which prevents DNS-rebinding style scope
escapes between validation and scanning.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]


class ScopeError(ValueError):
    """Raised when a target is malformed or outside the authorised scope."""


def _default_resolver(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"Cannot resolve hostname {hostname!r}") from exc
    return sorted({str(info[4][0]) for info in infos})


class TargetScope:
    """Validate and normalise scan targets against an allow-list."""

    def __init__(
        self,
        allowed: Iterable[str],
        max_hosts: int = 1024,
        resolver: Resolver | None = None,
    ) -> None:
        self.allowed: list[IPNetwork] = [ipaddress.ip_network(n, strict=False) for n in allowed]
        if not self.allowed:
            raise ValueError("At least one allowed network is required")
        self.max_hosts = max_hosts
        self._resolve = resolver or _default_resolver

    def _is_allowed_network(self, network: IPNetwork) -> bool:
        return any(
            network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self.allowed
        )

    def validate(self, target: str) -> str:
        """Return a normalised, in-scope target (IP or CIDR) or raise :class:`ScopeError`."""
        candidate = target.strip()
        if not candidate or len(candidate) > 255:
            raise ScopeError("Empty or oversized target")
        if any(ch in candidate for ch in " ;|&$`'\"<>(){}\\\n\r\t"):
            raise ScopeError(f"Illegal characters in target {candidate!r}")
        if candidate.startswith("-"):
            raise ScopeError("Targets must not start with '-' (option injection)")

        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            network = None

        if network is not None:
            if network.num_addresses > self.max_hosts:
                raise ScopeError(f"Target {candidate} covers {network.num_addresses} addresses (max {self.max_hosts})")
            if not self._is_allowed_network(network):
                raise ScopeError(f"Target {candidate} is outside the authorised scope")
            if network.num_addresses == 1:
                return str(network.network_address)
            return str(network)

        if not _HOSTNAME_RE.match(candidate):
            raise ScopeError(f"Invalid target {candidate!r}")
        addresses = self._resolve(candidate)
        if not addresses:
            raise ScopeError(f"Hostname {candidate!r} did not resolve")
        for address in addresses:
            ip_net = ipaddress.ip_network(address)
            if not self._is_allowed_network(ip_net):
                raise ScopeError(f"Hostname {candidate} resolves to {address}, outside the authorised scope")
        return addresses[0]

    def validate_many(self, targets: Iterable[str]) -> list[str]:
        """Validate a list of targets; de-duplicates while preserving order."""
        result: list[str] = []
        total = 0
        for target in targets:
            normalised = self.validate(target)
            total += ipaddress.ip_network(normalised, strict=False).num_addresses
            if total > self.max_hosts:
                raise ScopeError(f"Combined targets exceed the maximum of {self.max_hosts} hosts")
            if normalised not in result:
                result.append(normalised)
        if not result:
            raise ScopeError("No targets supplied")
        return result
