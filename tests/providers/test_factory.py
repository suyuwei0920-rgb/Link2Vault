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
from link2vault_providers.tencent_asr import TencentAsrProvider


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


def test_tencent_provider_builds_real_backend_from_complete_settings() -> None:
    settings = Settings(
        asr_provider="tencent",
        tencent_secret_id="synthetic-id",
        tencent_secret_key="synthetic-key",
        tencent_region="synthetic-region",
        tencent_cos_bucket="synthetic-bucket",
    )

    assert isinstance(build_asr_provider(settings), TencentAsrProvider)


def test_tencent_provider_fails_closed_when_any_required_setting_is_missing() -> None:
    settings = Settings(asr_provider="tencent")

    with pytest.raises(ProviderConfigurationError, match="TENCENT_SECRET_ID"):
        build_asr_provider(settings)
