from __future__ import annotations

import pytest
from link2vault.ingest.share_text import InvalidInput, extract_single_url

SHORT_ORIGIN = "https://" + "v." + "douyin.com"
WEB_ORIGIN = "https://" + "www." + "douyin.com"


def test_extracts_one_short_link_from_noisy_douyin_share_text() -> None:
    text = (
        "0.02 复制打开抖音，看看这个作品 "
        f"{SHORT_ORIGIN}/AbC_123/ 07/08 朋友分享"
    )

    assert extract_single_url(text) == f"{SHORT_ORIGIN}/AbC_123/"


@pytest.mark.parametrize(
    "text",
    [
        "这里没有链接",
        f"{SHORT_ORIGIN}/one/ {WEB_ORIGIN}/video/123",
    ],
)
def test_rejects_missing_or_multiple_links(text: str) -> None:
    with pytest.raises(InvalidInput, match="exactly one"):
        extract_single_url(text)
