import os
import warnings
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Check for .env file and warn if missing
ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.env"))
if not os.path.isfile(ENV_PATH):
    warnings.warn(
        f".env file not found at {ENV_PATH}. Using defaults and system environment variables.",
        stacklevel=1,
    )


class Settings(BaseSettings):
    # Metadata
    APP_NAME: str = "openremap"
    APP_ENV: str = "development"

    # MongoDB
    MONGO_URL: str = ""

    # Redis
    REDIS_URL: str = ""
    REDIS_ENABLED: bool = False
    CACHE_TTL: int = 300  # Default cache TTL in seconds (5 minutes)

    # Auth Tokens
    JWT_SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRY: int = 0
    REFRESH_TOKEN_EXPIRY: int = 0

    # Dashboard
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
    )

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        if v not in ("development", "production"):
            raise ValueError(
                f"Invalid APP_ENV: {v}. Must be 'development' or 'production'."
            )
        return v

    @field_validator("MONGO_URL")
    @classmethod
    def validate_mongo_url(cls, v: str) -> str:
        # MongoDB is currently disabled — MONGO_URL is optional.
        if not v:
            return v
        if not v.startswith("mongodb://") and not v.startswith("mongodb+srv://"):
            raise ValueError(
                "MONGO_URL must start with 'mongodb://' or 'mongodb+srv://'"
            )
        return v

    @property
    def database_name(self) -> str:
        """Get the database name based on environment."""
        return "prod_db" if self.APP_ENV == "production" else "dev_db"


settings = Settings()


# Optional: print loaded config for debug
# print(f"Configuration loaded: MONGO_URL={settings.MONGO_URL}, APP_ENV={settings.APP_ENV}, DB={settings.database_name}")
