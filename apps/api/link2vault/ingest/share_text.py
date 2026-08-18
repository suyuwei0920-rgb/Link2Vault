"""Extract one HTTP URL from noisy mobile share text."""

from __future__ import annotations

import re

from link2vault.ingest.remote_url import InvalidInput

_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCTUATION = "，。！？；：、）》】}>,.!?;:)]"


def extract_single_url(text: str) -> str:
    """Return exactly one URL or reject ambiguous/mistaken clipboard input."""

    urls = [match.rstrip(_TRAILING_PUNCTUATION) for match in _URL.findall(text)]
    if len(urls) != 1:
        raise InvalidInput(
            "INVALID_LINK_COUNT",
            "Share text must contain exactly one HTTP link",
        )
    return urls[0]
