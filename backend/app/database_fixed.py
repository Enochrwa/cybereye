# Fixed database.py with improved error handling and connection management

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from contextlib import asynccontextmanager
import logging
import asyncio
import time
from typing import AsyncGenerator

from .core.config import settings

# Import all models to ensure they're registered
from .models.user import User
from .models.log import Log
from .models.threat import ThreatLog
from .models.network import NetworkEvent
from .models.packet import Packets
from .models.firewall import FirewallLog, FirewallRule
from .models.ids_rule import IDSRule
from .models.config import AppConfig
from .models.system import SystemLog
from .models.ips import IPSRule, IPSEvent
from .models.base import Base

logger = logging.getLogger(__name__)

# Database configuration
SQLALCHEMY_DATABASE_URL = settings.SQLALCHEMY_DATABASE_URL

# Connection pool settings
if "sqlite" in SQLALCHEMY_DATABASE_URL:
    # SQLite configuration
    engine = create_async_engine(
        SQLALCHEMY_DATABASE_URL,
        poolclass=NullPool,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
        echo=settings.DEBUG,
        future=True,
    )
else:
    # PostgreSQL configuration
    engine = create_async_engine(
        SQLALCHEMY_DATABASE_URL,
        poolclass=QueuePool,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=settings.DEBUG,
        future=True,
    )

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Synchronous session for specific operations
if hasattr(engine, 'sync_engine'):
    SyncSessionLocal = sessionmaker(
        bind=engine.sync_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False
    )

class DatabaseManager:
    """Database manager with connection health monitoring."""
    
    def __init__(self):
        self.is_healthy = False
        self.last_health_check = 0
        self.health_check_interval = 30  # seconds
    
    async def check_health(self) -> bool:
        """Check database health."""
        now = time.time()
        if now - self.last_health_check < self.health_check_interval:
            return self.is_healthy
        
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(text("SELECT 1"))
                self.is_healthy = True
                self.last_health_check = now
                return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            self.is_healthy = False
            return False
    
    async def wait_for_database(self, max_retries: int = 30, delay: float = 1.0):
        """Wait for database to become available."""
        for attempt in range(max_retries):
            try:
                async with AsyncSessionLocal() as session:
                    await session.execute(text("SELECT 1"))
                logger.info("Database connection established")
                return True
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                    raise
                logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(delay)
        return False

db_manager = DatabaseManager()

async def init_db():
    """Initialize database tables with proper error handling."""
    try:
        logger.info("Initializing database...")
        
        # Wait for database to be available
        await db_manager.wait_for_database()
        
        async with engine.begin() as conn:
            # Check if tables exist
            tables_exist = await conn.run_sync(_check_tables_exist)
            
            if not tables_exist or settings.DEBUG:
                logger.info("Creating database tables...")
                
                # Drop all tables in development mode
                if settings.DEBUG:
                    await conn.run_sync(Base.metadata.drop_all)
                    logger.info("Dropped existing tables (development mode)")
                
                # Create all tables
                await conn.run_sync(Base.metadata.create_all)
                logger.info("Database tables created successfully")
                
                # Create default data
                await _create_default_data(conn)
            else:
                logger.info("Database tables already exist")
        
        # Verify database health
        if await db_manager.check_health():
            logger.info("Database initialization completed successfully")
        else:
            raise Exception("Database health check failed after initialization")
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def _check_tables_exist(conn) -> bool:
    """Check if database tables exist."""
    try:
        # Try to query a core table
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='users'"))
        return result.fetchone() is not None
    except:
        return False

async def _create_default_data(conn):
    """Create default data for the application."""
    try:
        from .core.security import get_password_hash
        
        # Create default admin user
        async with AsyncSessionLocal() as session:
            # Check if admin user exists
            result = await session.execute(text("SELECT id FROM users WHERE username = 'admin'"))
            if not result.fetchone():
                admin_user = User(
                    username="admin",
                    email="admin@ecyber.local",
                    hashed_password=get_password_hash("admin123"),
                    full_name="System Administrator",
                    is_active=True,
                    is_superuser=True,
                    is_two_factor_enabled=False
                )
                session.add(admin_user)
                await session.commit()
                logger.info("Created default admin user (username: admin, password: admin123)")
        
        # Create default configuration
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT id FROM app_config WHERE key = 'system_initialized'"))
            if not result.fetchone():
                config = AppConfig(
                    key="system_initialized",
                    value="true",
                    description="System initialization flag"
                )
                session.add(config)
                await session.commit()
                logger.info("Created default system configuration")
                
    except Exception as e:
        logger.error(f"Failed to create default data: {e}")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session with proper error handling."""
    if not await db_manager.check_health():
        raise HTTPException(
            status_code=503,
            detail="Database is not available"
        )
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except IntegrityError as e:
            await session.rollback()
            logger.error(f"Database integrity error: {str(e)}")
            raise ValueError("Data validation failed") from e
        except OperationalError as e:
            await session.rollback()
            logger.error(f"Database operational error: {str(e)}")
            raise RuntimeError("Database operation failed") from e
        except SQLAlchemyError as e:
            await session.rollback()
            logger.error(f"Database error: {str(e)}")
            if hasattr(e, 'statement'):
                logger.error(f"SQL Statement: {e.statement}")
            raise RuntimeError("Database operation failed") from e
        except Exception as e:
            await session.rollback()
            logger.error(f"Unexpected database error: {str(e)}")
            raise
        finally:
            await session.close()

@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database context error: {e}")
            raise
        finally:
            await session.close()

async def execute_with_retry(query, max_retries: int = 3, delay: float = 1.0):
    """Execute database query with retry logic."""
    for attempt in range(max_retries):
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(query)
                await session.commit()
                return result
        except OperationalError as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Database operation failed (attempt {attempt + 1}): {e}")
            await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
        except Exception as e:
            logger.error(f"Database operation failed: {e}")
            raise

# SQLite-specific event listeners
@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragmas for better performance and reliability."""
    if "sqlite" in SQLALCHEMY_DATABASE_URL:
        cursor = dbapi_connection.cursor()
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        # Set synchronous mode for better performance
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys=ON")
        # Set cache size (negative value means KB)
        cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
        # Set busy timeout
        cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        cursor.close()

# Connection pool event listeners
@event.listens_for(engine.sync_engine, "checkout")
def receive_checkout(dbapi_connection, connection_record, connection_proxy):
    """Handle connection checkout."""
    logger.debug("Database connection checked out")

@event.listens_for(engine.sync_engine, "checkin")
def receive_checkin(dbapi_connection, connection_record):
    """Handle connection checkin."""
    logger.debug("Database connection checked in")

# Cleanup function
async def cleanup_database():
    """Cleanup database connections."""
    try:
        await engine.dispose()
        logger.info("Database connections cleaned up")
    except Exception as e:
        logger.error(f"Error cleaning up database: {e}")

# Health check function
async def database_health_check() -> dict:
    """Perform comprehensive database health check."""
    health_info = {
        "status": "unhealthy",
        "connection": False,
        "tables": False,
        "response_time": None
    }
    
    start_time = time.time()
    
    try:
        # Test connection
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            health_info["connection"] = True
            
            # Test table access
            result = await session.execute(text("SELECT COUNT(*) FROM users"))
            if result.fetchone():
                health_info["tables"] = True
        
        health_info["response_time"] = time.time() - start_time
        health_info["status"] = "healthy"
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_info["error"] = str(e)
        health_info["response_time"] = time.time() - start_time
    
    return health_info

