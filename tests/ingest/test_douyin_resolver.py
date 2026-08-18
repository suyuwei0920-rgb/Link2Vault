from __future__ import annotations

from collections.abc import Mapping

import httpx
import pytest
from link2vault.ingest.douyin_resolver import DouyinResolver
from link2vault.ingest.remote_url import InvalidInput

SHORT_ORIGIN = "https://" + "v." + "douyin.com"
WEB_ORIGIN = "https://" + "www." + "douyin.com"


def ipv4(*octets: str) -> str:
    return ".".join(octets)


class FakeHostResolver:
    async def resolve(self, _host: str) -> tuple[str, ...]:
        return (ipv4("1", "1", "1", "1"),)


class FakeClient:
    def __init__(
        self,
        responses: Mapping[str, tuple[int, dict[str, str]] | tuple[int, dict[str, str], str]],
    ) -> None:
        self.responses = responses
        self.requested: list[str] = []

    async def get(self, url: str, *, follow_redirects: bool) -> httpx.Response:
        assert follow_redirects is False
        self.requested.append(url)
        fixture = self.responses[url]
        status, headers = fixture[:2]
        body = fixture[2] if len(fixture) == 3 else ""
        return httpx.Response(
            status,
            headers=headers,
            text=body,
            request=httpx.Request("GET", url),
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_redirect_leaving_page_allowlist_is_rejected_before_request() -> None:
    start = f"{SHORT_ORIGIN}/start/"
    untrusted = "https://" + "evil." + "example/video/1"
    client = FakeClient({start: (302, {"location": untrusted})})
    resolver = DouyinResolver(client=client, host_resolver=FakeHostResolver())

    with pytest.raises(InvalidInput, match="allowed"):
        await resolver.resolve(start)

    assert client.requested == [start]


@pytest.mark.anyio
async def test_more_than_five_redirects_is_rejected() -> None:
    urls = [f"{SHORT_ORIGIN}/step-{index}/" for index in range(7)]
    responses = {
        url: (302, {"location": urls[index + 1]})
        for index, url in enumerate(urls[:-1])
    }
    client = FakeClient(responses)
    resolver = DouyinResolver(client=client, host_resolver=FakeHostResolver())

    with pytest.raises(InvalidInput, match="redirect"):
        await resolver.resolve(urls[0])

    assert len(client.requested) == 6


@pytest.mark.anyio
async def test_classifies_canonical_profile_target() -> None:
    start = f"{SHORT_ORIGIN}/short/"
    final_url = f"{WEB_ORIGIN}/user/MS4wLjABAAAA-safe_id"
    client = FakeClient(
        {
            start: (302, {"location": final_url}),
            final_url: (200, {}),
        }
    )
    resolver = DouyinResolver(client=client, host_resolver=FakeHostResolver())

    target = await resolver.resolve(f"复制打开抖音 {start} 更多文字")

    assert target.kind == "profile"
    assert target.canonical_url == final_url
    assert target.media_candidates == ()


@pytest.mark.anyio
async def test_video_fetches_h5_router_data_and_extracts_media_candidate() -> None:
    start = f"{SHORT_ORIGIN}/short/"
    item_id = "1234567890"
    final_url = f"{WEB_ORIGIN}/video/{item_id}"
    h5_origin = "https://" + "www." + "iesdouyin.com"
    h5_url = f"{h5_origin}/share/video/{item_id}/"
    media_url = "https://" + "v3." + "douyinvod.com/synthetic.mp4"
    body = (
        '<script>window._ROUTER_DATA = {"loaderData":{"video":{"videoInfoRes":'
        f'{{"item_list":[{{"aweme_id":"{item_id}","desc":"安全标题",'
        f'"video":{{"play_addr":{{"url_list":["{media_url}"]}}}}}}]}}}}}}}}'
        "</script>"
    )
    client = FakeClient(
        {
            start: (302, {"location": final_url}),
            final_url: (200, {}),
            h5_url: (200, {}, body),
        }
    )
    resolver = DouyinResolver(client=client, host_resolver=FakeHostResolver())

    target = await resolver.resolve(start)

    assert target.kind == "video"
    assert target.canonical_url == final_url
    assert target.media_candidates == (media_url,)
    assert target.title == "安全标题"


@pytest.mark.anyio
async def test_rejects_noncanonical_final_path_before_paid_processing() -> None:
    url = f"{WEB_ORIGIN}/search/example"
    client = FakeClient({url: (200, {})})
    resolver = DouyinResolver(client=client, host_resolver=FakeHostResolver())

    with pytest.raises(InvalidInput, match="video or profile"):
        await resolver.resolve(url)
