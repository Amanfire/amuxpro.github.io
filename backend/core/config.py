"""Application settings loaded from environment variables."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://amux_user:password@localhost:5432/amux_db"
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "noreply@amuxapp.com"

    APP_NAME: str = "Amux Autoclicker Pro"
    FRONTEND_URL: str = "https://amuxapp.com"
    MAX_DEVICES_PER_LICENSE: int = 3

    class Config:
        env_file = ".env"


settings = Settings()
