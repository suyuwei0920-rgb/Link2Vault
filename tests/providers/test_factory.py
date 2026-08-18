from __future__ import annotations

import pytest
from link2vault.config import Settings
from link2vault.providers.factory import (
    ProviderConfigurationError,
    build_asr_provider,
    build_cleaner_provider,
    build_notifiers,
)
from link2vault_providers.fakes import FakeAsrProvider, FakeCleanerProvider


def test_default_configuration_builds_offline_providers() -> None:
    settings = Settings()

    assert isinstance(build_asr_provider(settings), FakeAsrProvider)
    assert isinstance(build_cleaner_provider(settings), FakeCleanerProvider)
    assert build_notifiers(settings) == ()


def test_selected_deepseek_provider_fails_before_work_without_credentials() -> None:
    settings = Settings(cleaner_provider="deepseek")

    with pytest.raises(ProviderConfigurationError, match="DeepSeek"):
        build_cleaner_provider(settings)


def test_unknown_provider_name_is_rejected() -> None:
    settings = Settings(asr_provider="unknown")

    with pytest.raises(ProviderConfigurationError, match="ASR"):
        build_asr_provider(settings)
