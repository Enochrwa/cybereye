# Server stability and continuous operation system

import asyncio
import signal
import sys
import os
import time
import logging
import threading
import subprocess
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import psutil
import uvicorn
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy import text, event
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

@dataclass
class HealthCheck:
    """Health check configuration."""
    name: str
    check_function: Callable
    interval: int  # seconds
    timeout: int   # seconds
    critical: bool = False
    last_check: Optional[datetime] = None
    last_result: Optional[bool] = None
    failure_count: int = 0
    max_failures: int = 3

class ServerStabilityManager:
    """Manages server stability and continuous operation."""
    
    def __init__(self):
        self.is_running = False
        self.start_time = None
        self.health_checks: Dict[str, HealthCheck] = {}
        self.restart_count = 0
        self.max_restarts = 10
        self.restart_window = 3600  # 1 hour
        self.restart_times = []
        
        # System monitoring
        self.cpu_threshold = 90.0  # %
        self.memory_threshold = 90.0  # %
        self.disk_threshold = 95.0  # %
        
        # Auto-recovery settings
        self.auto_restart_enabled = True
        self.graceful_shutdown_timeout = 30  # seconds
        
        # Background tasks
        self._monitoring_task = None
        self._health_check_task = None
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.graceful_shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Windows compatibility
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, signal_handler)
    
    async def start(self):
        """Start the stability manager."""
        self.is_running = True
        self.start_time = datetime.utcnow()
        
        logger.info("Starting server stability manager...")
        
        # Start background tasks
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        # Register default health checks
        await self._register_default_health_checks()
        
        logger.info("Server stability manager started successfully")
    
    async def stop(self):
        """Stop the stability manager."""
        self.is_running = False
        
        logger.info("Stopping server stability manager...")
        
        # Cancel background tasks
        if self._monitoring_task:
            self._monitoring_task.cancel()
        if self._health_check_task:
            self._health_check_task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(
            self._monitoring_task,
            self._health_check_task,
            return_exceptions=True
        )
        
        logger.info("Server stability manager stopped")
    
    async def _register_default_health_checks(self):
        """Register default health checks."""
        # Database connectivity check
        self.register_health_check(
            "database",
            self._check_database_health,
            interval=30,
            timeout=10,
            critical=True
        )
        
        # Memory usage check
        self.register_health_check(
            "memory",
            self._check_memory_health,
            interval=60,
            timeout=5,
            critical=False
        )
        
        # Disk space check
        self.register_health_check(
            "disk_space",
            self._check_disk_health,
            interval=300,  # 5 minutes
            timeout=5,
            critical=False
        )
        
        # CPU usage check
        self.register_health_check(
            "cpu",
            self._check_cpu_health,
            interval=60,
            timeout=5,
            critical=False
        )
    
    def register_health_check(
        self,
        name: str,
        check_function: Callable,
        interval: int = 60,
        timeout: int = 10,
        critical: bool = False,
        max_failures: int = 3
    ):
        """Register a health check."""
        self.health_checks[name] = HealthCheck(
            name=name,
            check_function=check_function,
            interval=interval,
            timeout=timeout,
            critical=critical,
            max_failures=max_failures
        )
        
        logger.info(f"Registered health check: {name}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.is_running:
            try:
                await self._monitor_system_resources()
                await self._check_restart_conditions()
                await asyncio.sleep(30)  # Monitor every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(10)
    
    async def _health_check_loop(self):
        """Health check loop."""
        while self.is_running:
            try:
                await self._run_health_checks()
                await asyncio.sleep(10)  # Check every 10 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(10)
    
    async def _monitor_system_resources(self):
        """Monitor system resources."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.cpu_threshold:
                logger.warning(f"High CPU usage: {cpu_percent}%")
                await self._handle_high_resource_usage("cpu", cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > self.memory_threshold:
                logger.warning(f"High memory usage: {memory.percent}%")
                await self._handle_high_resource_usage("memory", memory.percent)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > self.disk_threshold:
                logger.warning(f"High disk usage: {disk_percent}%")
                await self._handle_high_resource_usage("disk", disk_percent)
            
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
    
    async def _handle_high_resource_usage(self, resource_type: str, usage: float):
        """Handle high resource usage."""
        if resource_type == "memory":
            # Trigger garbage collection
            import gc
            gc.collect()
            
            # Clear caches if available
            try:
                from ..core.performance import cache_manager
                await cache_manager.clear_pattern("temp:*")
            except ImportError:
                pass
        
        elif resource_type == "cpu":
            # Reduce background task frequency temporarily
            await asyncio.sleep(5)
        
        elif resource_type == "disk":
            # Clean up temporary files
            await self._cleanup_temp_files()
    
    async def _cleanup_temp_files(self):
        """Clean up temporary files."""
        try:
            temp_dirs = ['/tmp', '/var/tmp', './logs', './temp']
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    # Remove files older than 24 hours
                    cutoff_time = time.time() - (24 * 3600)
                    
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                if os.path.getmtime(file_path) < cutoff_time:
                                    os.remove(file_path)
                            except (OSError, IOError):
                                pass  # File might be in use
            
            logger.info("Temporary files cleanup completed")
            
        except Exception as e:
            logger.error(f"Temp files cleanup error: {e}")
    
    async def _run_health_checks(self):
        """Run all health checks."""
        now = datetime.utcnow()
        
        for name, health_check in self.health_checks.items():
            # Check if it's time to run this health check
            if (health_check.last_check is None or 
                (now - health_check.last_check).total_seconds() >= health_check.interval):
                
                await self._run_single_health_check(health_check)
    
    async def _run_single_health_check(self, health_check: HealthCheck):
        """Run a single health check."""
        try:
            # Run the check with timeout
            result = await asyncio.wait_for(
                health_check.check_function(),
                timeout=health_check.timeout
            )
            
            health_check.last_check = datetime.utcnow()
            health_check.last_result = result
            
            if result:
                # Reset failure count on success
                health_check.failure_count = 0
            else:
                # Increment failure count
                health_check.failure_count += 1
                logger.warning(
                    f"Health check '{health_check.name}' failed "
                    f"({health_check.failure_count}/{health_check.max_failures})"
                )
                
                # Handle critical failures
                if (health_check.critical and 
                    health_check.failure_count >= health_check.max_failures):
                    await self._handle_critical_failure(health_check)
        
        except asyncio.TimeoutError:
            health_check.failure_count += 1
            logger.error(f"Health check '{health_check.name}' timed out")
        
        except Exception as e:
            health_check.failure_count += 1
            logger.error(f"Health check '{health_check.name}' error: {e}")
    
    async def _handle_critical_failure(self, health_check: HealthCheck):
        """Handle critical health check failure."""
        logger.critical(f"Critical health check '{health_check.name}' failed repeatedly")
        
        if self.auto_restart_enabled:
            await self._initiate_restart(f"Critical health check failure: {health_check.name}")
        else:
            # Send alert but don't restart
            logger.critical("Auto-restart disabled, manual intervention required")
    
    async def _check_restart_conditions(self):
        """Check if restart is needed."""
        # Check restart rate limiting
        now = datetime.utcnow()
        recent_restarts = [
            restart_time for restart_time in self.restart_times
            if (now - restart_time).total_seconds() < self.restart_window
        ]
        
        if len(recent_restarts) >= self.max_restarts:
            logger.error("Too many restarts in time window, disabling auto-restart")
            self.auto_restart_enabled = False
    
    async def _initiate_restart(self, reason: str):
        """Initiate server restart."""
        if not self.auto_restart_enabled:
            logger.warning(f"Restart requested ({reason}) but auto-restart is disabled")
            return
        
        logger.info(f"Initiating server restart: {reason}")
        
        # Record restart time
        self.restart_times.append(datetime.utcnow())
        self.restart_count += 1
        
        # Graceful shutdown and restart
        await self.graceful_shutdown()
        
        # Restart the process
        os.execv(sys.executable, [sys.executable] + sys.argv)
    
    async def graceful_shutdown(self):
        """Perform graceful shutdown."""
        logger.info("Starting graceful shutdown...")
        
        # Stop accepting new requests
        self.is_running = False
        
        # Wait for ongoing requests to complete
        await asyncio.sleep(2)
        
        # Stop background tasks
        await self.stop()
        
        # Close database connections
        try:
            from ..database import engine
            await engine.dispose()
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
        
        logger.info("Graceful shutdown completed")
    
    # Health check implementations
    async def _check_database_health(self) -> bool:
        """Check database connectivity."""
        try:
            from ..database import get_db
            
            async with get_db() as db:
                result = await db.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def _check_memory_health(self) -> bool:
        """Check memory usage."""
        try:
            memory = psutil.virtual_memory()
            return memory.percent < self.memory_threshold
        except Exception:
            return False
    
    async def _check_disk_health(self) -> bool:
        """Check disk space."""
        try:
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            return disk_percent < self.disk_threshold
        except Exception:
            return False
    
    async def _check_cpu_health(self) -> bool:
        """Check CPU usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            return cpu_percent < self.cpu_threshold
        except Exception:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get server status."""
        uptime = None
        if self.start_time:
            uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        health_status = {}
        for name, check in self.health_checks.items():
            health_status[name] = {
                'last_check': check.last_check.isoformat() if check.last_check else None,
                'last_result': check.last_result,
                'failure_count': check.failure_count,
                'critical': check.critical,
                'healthy': check.failure_count < check.max_failures
            }
        
        return {
            'is_running': self.is_running,
            'uptime_seconds': uptime,
            'restart_count': self.restart_count,
            'auto_restart_enabled': self.auto_restart_enabled,
            'health_checks': health_status,
            'system_resources': self._get_system_resources()
        }
    
    def _get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource usage."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
            }
        except Exception as e:
            logger.error(f"Error getting system resources: {e}")
            return {}

# Database connection optimization
class DatabaseConnectionManager:
    """Manage database connections for stability."""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = None
        self.connection_pool_size = 20
        self.max_overflow = 30
        self.pool_timeout = 30
        self.pool_recycle = 3600  # 1 hour
        
    def create_engine(self):
        """Create optimized database engine."""
        self.engine = create_async_engine(
            self.database_url,
            poolclass=QueuePool,
            pool_size=self.connection_pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_recycle=self.pool_recycle,
            pool_pre_ping=True,  # Validate connections
            echo=False,  # Set to True for SQL debugging
        )
        
        # Add connection event listeners
        @event.listens_for(self.engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            # SQLite optimizations
            if 'sqlite' in self.database_url:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=10000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
        
        return self.engine
    
    async def health_check(self) -> bool:
        """Check database connection health."""
        if not self.engine:
            return False
        
        try:
            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def close(self):
        """Close database connections."""
        if self.engine:
            await self.engine.dispose()

# Server lifecycle management
@asynccontextmanager
async def lifespan(app):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting eCyber Security Platform...")
    
    # Initialize stability manager
    stability_manager = ServerStabilityManager()
    app.state.stability_manager = stability_manager
    await stability_manager.start()
    
    # Initialize database
    from ..database import init_db
    await init_db()
    
    logger.info("eCyber Security Platform started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down eCyber Security Platform...")
    await stability_manager.stop()
    logger.info("eCyber Security Platform shutdown complete")

# Process management utilities
class ProcessManager:
    """Manage server processes and ensure continuous operation."""
    
    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """Check if port is in use."""
        import socket
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    @staticmethod
    def kill_process_on_port(port: int) -> bool:
        """Kill process running on specific port."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    for conn in proc.info['connections'] or []:
                        if conn.laddr.port == port:
                            proc.terminate()
                            proc.wait(timeout=5)
                            return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception as e:
            logger.error(f"Error killing process on port {port}: {e}")
            return False
    
    @staticmethod
    def start_server_daemon(
        host: str = "0.0.0.0",
        port: int = 8000,
        workers: int = 1,
        log_level: str = "info"
    ):
        """Start server as daemon process."""
        # Check if port is already in use
        if ProcessManager.is_port_in_use(port):
            logger.warning(f"Port {port} is already in use, attempting to kill existing process")
            ProcessManager.kill_process_on_port(port)
            time.sleep(2)
        
        # Configure uvicorn
        config = uvicorn.Config(
            "main:app",
            host=host,
            port=port,
            workers=workers,
            log_level=log_level,
            reload=False,
            access_log=True,
            use_colors=False,
            lifespan="on"
        )
        
        server = uvicorn.Server(config)
        
        # Run server
        try:
            server.run()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise

# Global stability manager instance
stability_manager = None

def get_stability_manager() -> Optional[ServerStabilityManager]:
    """Get global stability manager instance."""
    return stability_manager

# Export stability components
__all__ = [
    'ServerStabilityManager',
    'DatabaseConnectionManager',
    'ProcessManager',
    'lifespan',
    'get_stability_manager'
]

