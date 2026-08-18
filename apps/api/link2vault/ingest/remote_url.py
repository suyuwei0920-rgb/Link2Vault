"""SSRF-resistant validation for remote page and media URLs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

UrlRole = Literal["page", "media"]

_PAGE_DOMAINS = (
    "douyin.com",
    "iesdouyin.com",
)
_MEDIA_DOMAINS = (
    "douyin.com",
    "douyinvod.com",
    "bytecdntp.com",
    "zjcdn.com",
    "douyinpic.com",
)


class InvalidInput(ValueError):
    """Typed, redacted input error safe to expose before paid stages."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class HostResolver(Protocol):
    """Resolve all addresses for a hostname."""

    async def resolve(self, host: str) -> tuple[str, ...]: ...


class SocketHostResolver:
    """Resolve through the operating system without blocking the event loop."""

    async def resolve(self, host: str) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(
            host,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return tuple(sorted({record[4][0] for record in records}))


@dataclass(frozen=True)
class ValidatedUrl:
    """A URL whose authority, allowlist and current DNS answers are safe."""

    url: str
    host: str
    addresses: tuple[str, ...]


def _host_allowed(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


async def validate_remote_url(
    url: str,
    role: UrlRole,
    resolver: HostResolver,
) -> ValidatedUrl:
    """Validate one URL immediately before an outbound request."""

    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise InvalidInput("INVALID_URL", "Remote URL is malformed")
    try:
        parsed = urlsplit(url)
        remote_name = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InvalidInput("INVALID_URL", "Remote URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or remote_name is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise InvalidInput("INVALID_URL", "Remote URL must use a safe HTTPS authority")
    if (
        not remote_name.isascii()
        or remote_name.endswith(".")
        or remote_name != remote_name.casefold()
    ):
        raise InvalidInput("INVALID_HOST", "Remote host is malformed")
    try:
        ipaddress.ip_address(remote_name)
    except ValueError:
        pass
    else:
        raise InvalidInput("IP_HOST_FORBIDDEN", "Numeric remote hosts are not allowed")
    domains = _PAGE_DOMAINS if role == "page" else _MEDIA_DOMAINS
    if not _host_allowed(remote_name, domains):
        raise InvalidInput("HOST_NOT_ALLOWED", "Remote host is not allowed")
    try:
        addresses = await resolver.resolve(remote_name)
    except (OSError, UnicodeError) as exc:
        raise InvalidInput("DNS_FAILED", "Remote host could not be resolved") from exc
    if not addresses:
        raise InvalidInput("DNS_FAILED", "Remote host could not be resolved")
    try:
        parsed_addresses = tuple(ipaddress.ip_address(value) for value in addresses)
    except ValueError as exc:
        raise InvalidInput("DNS_FAILED", "Remote host returned an invalid address") from exc
    if any(
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        for address in parsed_addresses
    ):
        raise InvalidInput(
            "NON_PUBLIC_ADDRESS",
            "Remote host must resolve only to the public network",
        )
    return ValidatedUrl(url=url, host=remote_name, addresses=tuple(addresses))
