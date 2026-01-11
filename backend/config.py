import os
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "Spectre C2 Tactical Bridge"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    ALLOWED_HOSTS: list = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://spectre:spectre_secure_pass@localhost:5432/spectre_c2"
    )
    
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 3600
    
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_USE_STRONG_SECRET_KEY")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    LEGACY_AUTH_TOKEN: str = "valid_token"
    
    FILE_STORAGE_PATH: str = os.getenv("FILE_STORAGE_PATH", "./storage")
    IQ_RECORDINGS_PATH: str = os.path.join(FILE_STORAGE_PATH, "iq_recordings")
    EVIDENCE_FILES_PATH: str = os.path.join(FILE_STORAGE_PATH, "evidence")
    REPORTS_PATH: str = os.path.join(FILE_STORAGE_PATH, "reports")
    MAX_UPLOAD_SIZE: int = 1024 * 1024 * 1024
    
    SDR_SAMPLE_RATE: int = 2_400_000
    SDR_CENTER_FREQ: int = 437_500_000
    SDR_GAIN: str = "auto"
    SDR_PPM: int = 0
    
    CELESTRAK_BASE_URL: str = "https://celestrak.org"
    CELESTRAK_API_KEY: Optional[str] = os.getenv("CELESTRAK_API_KEY")
    SPACETRACK_USERNAME: Optional[str] = os.getenv("SPACETRACK_USERNAME")
    SPACETRACK_PASSWORD: Optional[str] = os.getenv("SPACETRACK_PASSWORD")
    SPACETRACK_API_KEY: Optional[str] = os.getenv("SPACETRACK_API_KEY")
    N2YO_API_KEY: Optional[str] = os.getenv("N2YO_API_KEY")
    SATNOGS_API_KEY: Optional[str] = os.getenv("SATNOGS_API_KEY")
    
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002"
    ]
    
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    ENABLE_SDR_HARDWARE: bool = os.getenv("ENABLE_SDR_HARDWARE", "false").lower() == "true"
    ENABLE_GNU_RADIO: bool = os.getenv("ENABLE_GNU_RADIO", "false").lower() == "true"
    ENABLE_HAMLIB: bool = os.getenv("ENABLE_HAMLIB", "false").lower() == "true"
    
    ROTCTLD_HOST: str = "localhost"
    ROTCTLD_PORT: int = 4533
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
