"""Application settings for the public service."""

import os

from pydantic_settings import BaseSettings, SettingsConfigDict

_ENVIRONMENT_PREFIX = "LINK2VAULT_"
_ALLOWED_ENVIRONMENT_VARIABLES = frozenset(
    {
        "LINK2VAULT_APP_NAME",
        "LINK2VAULT_APP_ENV",
        "LINK2VAULT_HOST",
        "LINK2VAULT_PORT",
    }
)


class Settings(BaseSettings):
    """Configuration loaded from explicitly supported environment variables."""

    model_config = SettingsConfigDict(env_prefix=_ENVIRONMENT_PREFIX, extra="forbid")

    app_name: str = "Link2Vault"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000

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
