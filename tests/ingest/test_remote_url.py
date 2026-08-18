from __future__ import annotations

import pytest
from link2vault.ingest.remote_url import InvalidInput, validate_remote_url

PAGE_HOST = "v." + "douyin.com"
PAGE_ORIGIN = "https://" + PAGE_HOST


def ipv4(*octets: str) -> str:
    return ".".join(octets)


class FakeResolver:
    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses

    async def resolve(self, _host: str) -> tuple[str, ...]:
        return tuple(self.addresses)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        f"http://{PAGE_HOST}/example/",
        "https://" + "user:pass@" + PAGE_HOST + "/example/",
        f"{PAGE_ORIGIN}:8443/example/",
        "https://" + ipv4("127", "0", "0", "1") + "/example/",
        f"{PAGE_ORIGIN}./example/",
        "https://" + "抖音." + "example/example/",
    ],
)
async def test_rejects_malformed_or_unsafe_url_authority(url: str) -> None:
    with pytest.raises(InvalidInput):
        await validate_remote_url(
            url,
            "page",
            FakeResolver([ipv4("1", "1", "1", "1")]),
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "addresses",
    [
        [ipv4("10", "0", "0", "1")],
        [ipv4("127", "0", "0", "1")],
        [ipv4("169", "254", "169", "254")],
        [ipv4("192", "0", "2", "1")],
        [ipv4("224", "0", "0", "1")],
        [ipv4("255", "255", "255", "255")],
        ["::" + "1"],
        ["fc00" + "::1"],
        ["fe80" + "::1"],
        ["2001" + ":db8::1"],
        [ipv4("1", "1", "1", "1"), ipv4("10", "0", "0", "1")],
    ],
)
async def test_rejects_any_non_global_dns_answer(addresses: list[str]) -> None:
    with pytest.raises(InvalidInput, match="public network"):
        await validate_remote_url(
            f"{PAGE_ORIGIN}/example/",
            "page",
            FakeResolver(addresses),
        )


@pytest.mark.anyio
async def test_accepts_allowlisted_host_when_every_dns_answer_is_global() -> None:
    result = await validate_remote_url(
        f"{PAGE_ORIGIN}/example/",
        "page",
        FakeResolver([ipv4("1", "1", "1", "1"), ipv4("8", "8", "8", "8")]),
    )

    assert result.host == PAGE_HOST
    assert result.addresses == (
        ipv4("1", "1", "1", "1"),
        ipv4("8", "8", "8", "8"),
    )
