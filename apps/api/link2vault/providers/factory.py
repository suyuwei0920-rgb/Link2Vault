"""Fail-closed construction of configured provider adapters."""

from __future__ import annotations

from collections.abc import Callable

import httpx
from link2vault_providers.bark import BarkNotifier
from link2vault_providers.contracts import (
    AsrProvider,
    CleanerProvider,
    NotifierProvider,
)
from link2vault_providers.deepseek_cleaner import DeepSeekCleaner
from link2vault_providers.fakes import FakeAsrProvider, FakeCleanerProvider
from link2vault_providers.openai_asr import OpenAICompatibleAsrProvider
from link2vault_providers.tencent_asr import (
    TencentAsrBackend,
    TencentAsrProvider,
    TencentQuotaSnapshot,
)
from link2vault_providers.webhook import WebhookNotifier

from link2vault.config import Settings


class ProviderConfigurationError(ValueError):
    """Safe startup error containing variable names, never values."""


def build_asr_provider(
    settings: Settings,
    *,
    tencent_backend: TencentAsrBackend | None = None,
    quota_loader: Callable[[], TencentQuotaSnapshot] | None = None,
) -> AsrProvider:
    if settings.asr_provider == "fake":
        return FakeAsrProvider()
    if settings.asr_provider == "openai-compatible":
        if not all((settings.asr_base_url, settings.asr_api_key, settings.asr_model)):
            raise ProviderConfigurationError(
                "ASR configuration requires ASR_BASE_URL, ASR_API_KEY and ASR_MODEL"
            )
        client = httpx.AsyncClient(
            base_url=settings.asr_base_url,
            timeout=httpx.Timeout(120),
        )
        return OpenAICompatibleAsrProvider(
            api_key=settings.asr_api_key.get_secret_value(),
            model=settings.asr_model,
            client=client,
        )
    if settings.asr_provider == "tencent":
        if tencent_backend is None or quota_loader is None:
            raise ProviderConfigurationError(
                "Tencent ASR requires a configured backend and prepaid quota loader"
            )
        return TencentAsrProvider(
            backend=tencent_backend,
            quota_loader=quota_loader,
        )
    raise ProviderConfigurationError("Unknown ASR provider")


def build_cleaner_provider(settings: Settings) -> CleanerProvider:
    if settings.cleaner_provider == "fake":
        return FakeCleanerProvider()
    if settings.cleaner_provider == "deepseek":
        if settings.deepseek_base_url is None or settings.deepseek_api_key is None:
            raise ProviderConfigurationError(
                "DeepSeek configuration requires DEEPSEEK_BASE_URL and DEEPSEEK_API_KEY"
            )
        client = httpx.AsyncClient(
            base_url=settings.deepseek_base_url,
            timeout=httpx.Timeout(60),
        )
        return DeepSeekCleaner(
            api_key=settings.deepseek_api_key.get_secret_value(),
            model=settings.deepseek_model,
            client=client,
        )
    raise ProviderConfigurationError("Unknown cleaner provider")


def build_notifiers(settings: Settings) -> tuple[NotifierProvider, ...]:
    notifiers: list[NotifierProvider] = []
    if settings.bark_base_url is not None or settings.bark_device_key is not None:
        if settings.bark_base_url is None or settings.bark_device_key is None:
            raise ProviderConfigurationError(
                "Bark requires BARK_BASE_URL and BARK_DEVICE_KEY"
            )
        notifiers.append(
            BarkNotifier(
                base_url=settings.bark_base_url,
                device_key=settings.bark_device_key.get_secret_value(),
            )
        )
    if settings.webhook_url is not None or settings.webhook_signing_secret is not None:
        if settings.webhook_url is None or settings.webhook_signing_secret is None:
            raise ProviderConfigurationError(
                "Webhook requires WEBHOOK_URL and WEBHOOK_SIGNING_SECRET"
            )
        notifiers.append(
            WebhookNotifier(
                endpoint=settings.webhook_url,
                signing_secret=settings.webhook_signing_secret.get_secret_value().encode(),
            )
        )
    return tuple(notifiers)
