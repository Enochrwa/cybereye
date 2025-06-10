# Fixed configuration with environment variables and security improvements

from pydantic import AnyHttpUrl, validator
from typing import List, Optional, Union
from pydantic_settings import BaseSettings
import os

class Settings(BaseSettings):
    # Application settings
    PROJECT_NAME: str = "eCyber - Real-time Cyber Threat Detection System"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Advanced real-time network threat detection and prevention API"
    
    # Environment
    ENVIRONMENT: str = "development"  # development, staging, production
    DEBUG: bool = False
    DOCS: bool = True
    PRODUCTION: bool = False
    
    # Security settings
    SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database settings
    SQLALCHEMY_DATABASE_URL: str = "sqlite+aiosqlite:///./security.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    
    # CORS settings
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4000",
        "http://127.0.0.1:4000",
        "http://localhost:5173",  # Vite dev server
        "http://127.0.0.1:5173",
    ]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Network settings
    NETWORK_INTERFACE: str = "Wi-Fi"
    REQUIRE_SOCKET_AUTH: bool = True
    
    # Redis settings (for production scaling)
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"
    ACCESS_LOG_FILE: str = "logs/access.log"
    ERROR_LOG_FILE: str = "logs/error.log"
    
    # External API settings
    FIREWALL_API_URL: Optional[str] = "http://127.0.0.1:8000/api/firewall"
    FIREWALL_API_KEY: Optional[str] = None
    
    THREAT_INTEL_API_URL: Optional[str] = "http://127.0.0.1:8000/api/intel/update"
    
    NAC_API_URL: Optional[str] = "http://127.0.0.1:8000/api/nac/quarantine"
    
    DNS_CONTROLLER_API_URL: Optional[str] = "http://127.0.0.1:8000/api/dns"
    DNS_CONTROLLER_API_KEY: Optional[str] = None
    
    DASHBOARD_API_URL: Optional[str] = "http://localhost:8081"
    DASHBOARD_API_KEY: Optional[str] = None
    DASHBOARD_MAX_RETRIES: int = 3
    DASHBOARD_RETRY_DELAY: int = 5
    DASHBOARD_TIMEOUT: int = 10
    
    # GeoIP Service
    GEOIP_SERVICE_URL_TEMPLATE: str = "http://ip-api.com/json/{ip}"
    
    # Threat Intelligence feeds
    THREATFOX_URL: str = "https://threatfox.abuse.ch/export/json/recent/"
    CIRCL_CVE_URL: str = "https://cve.circl.lu/api/last/10"
    THREAT_INTEL_UPDATE_INTERVAL: int = 3600  # seconds
    
    # ML Model settings
    ML_MODEL_PATH: str = "models/"
    ML_MODEL_UPDATE_INTERVAL: int = 86400  # 24 hours
    
    # Packet processing
    PACKET_QUEUE_SIZE: int = 10000
    PACKET_PROCESSING_WORKERS: int = 4
    
    # IPS settings
    IPS_RULES_PATH: str = "rules.json"
    IPS_BLOCK_DURATION: int = 3600  # seconds
    IPS_MAX_CONNECTIONS: int = 1000
    
    # Monitoring
    SYSTEM_MONITOR_INTERVAL: int = 5  # seconds
    NETWORK_MONITOR_INTERVAL: int = 1  # seconds
    
    # Email settings (for notifications)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    
    # Notification settings
    ENABLE_EMAIL_NOTIFICATIONS: bool = False
    ENABLE_WEBHOOK_NOTIFICATIONS: bool = False
    WEBHOOK_URL: Optional[str] = None
    
    # Backup settings
    BACKUP_ENABLED: bool = True
    BACKUP_INTERVAL: int = 86400  # 24 hours
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_PATH: str = "backups/"
    
    # Performance settings
    ENABLE_CACHING: bool = True
    CACHE_TTL: int = 300  # 5 minutes
    ENABLE_COMPRESSION: bool = True
    
    # Security headers
    ENABLE_SECURITY_HEADERS: bool = True
    ENABLE_HTTPS_REDIRECT: bool = False  # Set to True in production with HTTPS
    
    @validator("SECRET_KEY", pre=True)
    def validate_secret_key(cls, v: str) -> str:
        if not v:
            import secrets
            generated_key = secrets.token_urlsafe(32)
            print(f"WARNING: No SECRET_KEY provided. Generated: {generated_key}")
            print("Please set SECRET_KEY environment variable for production!")
            return generated_key
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v
    
    @validator("PRODUCTION", pre=True, always=True)
    def set_production_flag(cls, v, values):
        return values.get("ENVIRONMENT") == "production"
    
    @validator("DEBUG", pre=True, always=True)
    def set_debug_flag(cls, v, values):
        return values.get("ENVIRONMENT") == "development"
    
    @validator("DOCS", pre=True, always=True)
    def set_docs_flag(cls, v, values):
        return values.get("ENVIRONMENT") != "production"
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"

# Create settings instance
settings = Settings()

# Environment-specific overrides
if settings.PRODUCTION:
    # Production-specific settings
    settings.SQLALCHEMY_DATABASE_URL = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://user:password@localhost/ecyber_prod"
    )
    settings.BACKEND_CORS_ORIGINS = [
        "https://ecyber.vercel.app",
        "http://localhost:4000",
        "https://ecyber-ten.vercel.app",
        "https://your-production-domain.com"
    ]
    settings.ENABLE_HTTPS_REDIRECT = True
    settings.RATE_LIMIT_REQUESTS = 50  # Stricter rate limiting in production
    
elif settings.ENVIRONMENT == "staging":
    # Staging-specific settings
    settings.SQLALCHEMY_DATABASE_URL = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://user:password@localhost/ecyber_staging"
    )
    settings.BACKEND_CORS_ORIGINS.extend([
        "https://staging.ecyber.com"
    ])

# Validate critical settings
if settings.PRODUCTION and settings.SECRET_KEY.startswith("generated_"):
    raise ValueError("Production environment requires a proper SECRET_KEY")

if settings.PRODUCTION and "sqlite" in settings.SQLALCHEMY_DATABASE_URL:
    print("WARNING: Using SQLite in production is not recommended. Use PostgreSQL instead.")

# Export commonly used settings
DATABASE_URL = settings.SQLALCHEMY_DATABASE_URL
SECRET_KEY = settings.SECRET_KEY
DEBUG = settings.DEBUG
PRODUCTION = settings.PRODUCTION

