from __future__ import annotations

import httpx
import pytest
from link2vault.ingest.media_downloader import DouyinMediaDownloader, MediaDownloadError


def ipv4(*octets: str) -> str:
    return ".".join(octets)


class FakeHostResolver:
    async def resolve(self, _host: str) -> tuple[str, ...]:
        return (ipv4("1", "1", "1", "1"),)


class FakeClient:
    def __init__(self, responses: dict[str, tuple[int, dict[str, str], bytes]]) -> None:
        self.responses = responses
        self.requested: list[str] = []

    def build_request(self, method: str, url: str) -> httpx.Request:
        assert method == "GET"
        return httpx.Request(method, url)

    async def send(self, request: httpx.Request, *, stream: bool) -> httpx.Response:
        assert stream is True
        url = str(request.url)
        self.requested.append(url)
        status, headers, body = self.responses[url]
        return httpx.Response(
            status,
            headers=headers,
            stream=httpx.ByteStream(body),
            request=request,
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_download_validates_redirect_and_atomically_writes_bounded_media(
    tmp_path,
) -> None:
    first = "https://" + "v3." + "douyinvod.com/first"
    final = "https://" + "v6." + "douyinvod.com/final"
    client = FakeClient(
        {
            first: (302, {"location": final}, b""),
            final: (200, {"content-type": "video/mp4"}, b"synthetic-media"),
        }
    )
    downloader = DouyinMediaDownloader(
        media_root=tmp_path,
        client=client,
        host_resolver=FakeHostResolver(),
        max_bytes=1024,
    )

    output = await downloader.download((first,), "safe-task")

    assert output == tmp_path / "safe-task" / "source.media"
    assert output.read_bytes() == b"synthetic-media"
    assert client.requested == [first, final]
    assert list(output.parent.glob("*.partial")) == []


@pytest.mark.anyio
async def test_download_rejects_declared_oversize_before_writing(tmp_path) -> None:
    url = "https://" + "v3." + "douyinvod.com/large"
    client = FakeClient(
        {
            url: (
                200,
                {"content-type": "video/mp4", "content-length": "2048"},
                b"x",
            )
        }
    )
    downloader = DouyinMediaDownloader(
        media_root=tmp_path,
        client=client,
        host_resolver=FakeHostResolver(),
        max_bytes=1024,
    )

    with pytest.raises(MediaDownloadError) as captured:
        await downloader.download((url,), "safe-task")

    assert captured.value.code == "MEDIA_TOO_LARGE"
    assert not (tmp_path / "safe-task" / "source.media").exists()
