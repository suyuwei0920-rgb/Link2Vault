from __future__ import annotations

from link2vault_providers.contracts import ProviderError


def test_provider_error_string_contains_only_safe_message() -> None:
    secret = "DUMMY_" + "provider-key"
    transcript = "private customer transcript"
    error = ProviderError(
        "UPSTREAM_FAILED",
        retryable=False,
        safe_message="Provider request failed",
        provider_request_id="synthetic-request",
    )

    rendered = str(error)

    assert rendered == "Provider request failed"
    assert secret not in rendered
    assert transcript not in rendered
