"""Application settings for the public service."""

import os
import secrets
import tempfile
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENVIRONMENT_PREFIX = "LINK2VAULT_"
_ALLOWED_ENVIRONMENT_VARIABLES = frozenset(
    {
        "LINK2VAULT_APP_NAME",
        "LINK2VAULT_APP_ENV",
        "LINK2VAULT_HOST",
        "LINK2VAULT_PORT",
        "LINK2VAULT_DATA_DIR",
        "LINK2VAULT_TOKEN_PEPPER",
        "LINK2VAULT_PUBLIC_BASE_URL",
        "LINK2VAULT_CSRF_SIGNING_KEY",
        "LINK2VAULT_MEDIA_TMP_DIR",
        "LINK2VAULT_MAX_UPLOAD_MB",
        "LINK2VAULT_MAX_AUDIO_MINUTES",
        "LINK2VAULT_MONTHLY_AUDIO_MINUTES",
        "LINK2VAULT_VAULT_ROOT",
        "LINK2VAULT_ASR_PROVIDER",
        "LINK2VAULT_ASR_BASE_URL",
        "LINK2VAULT_ASR_API_KEY",
        "LINK2VAULT_ASR_MODEL",
        "LINK2VAULT_CLEANER_PROVIDER",
        "LINK2VAULT_DEEPSEEK_BASE_URL",
        "LINK2VAULT_DEEPSEEK_API_KEY",
        "LINK2VAULT_DEEPSEEK_MODEL",
        "LINK2VAULT_BARK_BASE_URL",
        "LINK2VAULT_BARK_DEVICE_KEY",
        "LINK2VAULT_WEBHOOK_URL",
        "LINK2VAULT_WEBHOOK_SIGNING_SECRET",
    }
)


class Settings(BaseSettings):
    """Configuration loaded from explicitly supported environment variables."""

    model_config = SettingsConfigDict(env_prefix=_ENVIRONMENT_PREFIX, extra="forbid")

    app_name: str = "Link2Vault"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    data_dir: Path = Path(tempfile.gettempdir()) / "link2vault-development"
    token_pepper: SecretStr = Field(
        default_factory=lambda: SecretStr(secrets.token_urlsafe(32))
    )
    public_base_url: str = "https://example.invalid"
    csrf_signing_key: SecretStr = Field(
        default_factory=lambda: SecretStr(secrets.token_urlsafe(32))
    )
    media_tmp_dir: Path = Path(tempfile.gettempdir()) / "link2vault-media"
    max_upload_mb: int = Field(default=1024, ge=1, le=1024)
    max_audio_minutes: int = Field(default=240, ge=1, le=240)
    monthly_audio_minutes: int = Field(default=600, ge=1)
    vault_root: Path = Path(tempfile.gettempdir()) / "link2vault-vault"
    asr_provider: str = "fake"
    asr_base_url: str | None = None
    asr_api_key: SecretStr | None = None
    asr_model: str | None = None
    cleaner_provider: str = "fake"
    deepseek_base_url: str | None = None
    deepseek_api_key: SecretStr | None = None
    deepseek_model: str = "deepseek-chat"
    bark_base_url: str | None = None
    bark_device_key: SecretStr | None = None
    webhook_url: str | None = None
    webhook_signing_secret: SecretStr | None = None

    def __init__(self, **values: object) -> None:
        unknown_variables = sorted(
            name
            for name in os.environ
            if name.startswith(_ENVIRONMENT_PREFIX)
            and name not in _ALLOWED_ENVIRONMENT_VARIABLES
        )
        if unknown_variables:
            unknown = ", ".join(unknown_variables)
            raise ValueError(f"Unsupported Link2Vault environment variables: {unknown}")
        super().__init__(**values)
