# Fixed main.py with proper server stability and resource management

from contextlib import asynccontextmanager
from datetime import datetime
import asyncio
import logging
import time
import os
import signal
import sys
from typing import Optional
from scapy.all import get_if_list
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import socketio
from multiprocessing import Queue, Manager
import multiprocessing
from queue import Full, Empty
import psutil

# Configuration
from app.core.config import settings

# API routes
from app.api.v1.api import api_v1_router

# Core components
from app.core.logger import setup_logger
from socket_events import get_socket_app
from app.services.system.monitor import SystemMonitor

# Database
from sqlalchemy.ext.asyncio import AsyncEngine
from app.database import engine, Base, AsyncSessionLocal, init_db

# Routers
from app.api import (
    users as user_router,
    network as network_router,
    auth as auth_router,
    threats as threat_router,
    models as ml_models_router,
    system as system_router,
    admin as admin_router,
)
from app.api.v1.endpoints.threats import router as ml_threats
from api.firewall_api import router as firewall_router
from api.threat_intel_api import router as intel_router
from api.nac_api import router as nac_router
from api.dns_api import router as dns_router
from api.ml_models_api import router as ml_models_api_router

# Utilities
from app.utils.report import (
    get_24h_network_traffic,
    get_daily_threat_summary,
    handle_network_history,
)

# Services
from app.services.monitoring.sniffer import PacketSniffer
from app.services.detection.signature import SignatureEngine
from app.services.ips.engine import EnterpriseIPS, ThreatIntel
from app.services.prevention.firewall import FirewallManager

# Socket.IO
from sio_instance import sio
from packet_sniffer_service import PacketSnifferService
from packet_sniffer_events import PacketSnifferNamespace
from malware_events_namespace import MalwareEventsNamespace

# Logging setup
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)
setup_logger("main", "INFO")
logger = logging.getLogger(__name__)

# Global service instances
sniffer: Optional[PacketSniffer] = None
sniffer_service: Optional[PacketSnifferService] = None
monitor: Optional[SystemMonitor] = None
ips: Optional[EnterpriseIPS] = None
startup_start_time = time.time()
server_ready_emitted = False
shutdown_event = asyncio.Event()

class ServiceManager:
    """Manages all application services with proper lifecycle."""
    
    def __init__(self):
        self.services = {}
        self.cleanup_tasks = []
    
    def register_service(self, name: str, service, cleanup_func=None):
        """Register a service with optional cleanup function."""
        self.services[name] = service
        if cleanup_func:
            self.cleanup_tasks.append(cleanup_func)
    
    async def cleanup_all(self):
        """Cleanup all registered services."""
        logger.info("Starting service cleanup...")
        for cleanup_func in reversed(self.cleanup_tasks):
            try:
                if asyncio.iscoroutinefunction(cleanup_func):
                    await cleanup_func()
                else:
                    cleanup_func()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")
        logger.info("Service cleanup completed")

service_manager = ServiceManager()

async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Proper lifespan management with error handling."""
        try:
            # Initialize database
            await init_db()
            logger.info("Database initialized successfully")
            
            # Initialize services
            await initialize_services(app)
            logger.info("🚀 CyberWatch Security System started successfully")
            
            # Setup signal handlers for graceful shutdown
            setup_signal_handlers()
            
            yield
            
        except Exception as e:
            logger.critical(f"Failed to start application: {e}")
            raise
        finally:
            # Cleanup services
            await cleanup_services()
            logger.info("🛑 Application shutdown completed")
    
    # Initialize FastAPI app
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=settings.DESCRIPTION,
        docs_url="/api/docs" if settings.DOCS else None,
        redoc_url="/api/redoc" if settings.DOCS else None,
        lifespan=lifespan
    )
    
    # Configure middleware
    configure_middleware(app)
    
    # Register routes
    register_routes(app)
    
    # Mount Socket.IO app
    socket_app = get_socket_app(app)
    app.mount("/socket.io", socket_app)
    
    return app

async def initialize_services(app: FastAPI):
    """Initialize all application services."""
    global sniffer, sniffer_service, monitor, ips
    
    try:
        # Initialize core services
        firewall = FirewallManager(sio)
        signature_engine = SignatureEngine(sio)
        
        # Initialize packet processing components
        manager = Manager()
        sio_queue = manager.Queue(maxsize=10000)
        output_queue = Queue()
        
        # Register Socket.IO namespaces
        sniffer_namespace = PacketSnifferNamespace("/packet_sniffer", sio_queue)
        sio.register_namespace(sniffer_namespace)
        
        malware_events_ns = MalwareEventsNamespace("/malware_events")
        sio.register_namespace(malware_events_ns)
        logger.info("Socket.IO namespaces registered")
        
        # Initialize threat intelligence
        intel = ThreatIntel()
        await intel.load_from_cache()
        asyncio.create_task(intel.fetch_and_cache_feeds())
        
        # Initialize IPS
        rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        ips = EnterpriseIPS(
            rules_path,
            sio,
            intel,
            multiprocessing.cpu_count(),
            sio_queue,
            output_queue,
        )
        
        # Initialize packet sniffer
        sniffer = PacketSniffer(sio_queue)
        sniffer_service = PacketSnifferService(sio, sio_queue)
        
        # Initialize system monitor
        monitor = SystemMonitor(sio)
        
        # Start services
        await monitor.start()
        await ips.start()
        
        # Store services in app state
        app.state.firewall = firewall
        app.state.signature_engine = signature_engine
        app.state.ips_engine = ips
        app.state.monitor = monitor
        app.state.sniffer = sniffer
        app.state.sniffer_service = sniffer_service
        app.state.db = AsyncSessionLocal
        
        # Register services for cleanup
        service_manager.register_service("monitor", monitor, monitor.stop)
        service_manager.register_service("ips", ips, ips.stop)
        service_manager.register_service("sniffer_service", sniffer_service, sniffer_service.stop)
        service_manager.register_service("database", engine, engine.dispose)
        
        logger.info("All services initialized successfully")
        
    except Exception as e:
        logger.error(f"Service initialization failed: {e}")
        raise

async def cleanup_services():
    """Cleanup all services gracefully."""
    global sniffer, sniffer_service, monitor, ips
    
    try:
        await service_manager.cleanup_all()
        
        # Additional cleanup
        if sniffer:
            sniffer.stop()
        
        # Set shutdown event
        shutdown_event.set()
        
    except Exception as e:
        logger.error(f"Error during service cleanup: {e}")

def configure_middleware(app: FastAPI):
    """Configure application middleware."""
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
            "https://ecyber.vercel.app",
            "https://ecyber-ten.vercel.app",
            "*" if settings.DEBUG else ""  # Allow all origins in debug mode
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    
    # Trusted host middleware for production
    if settings.PRODUCTION:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["localhost", "127.0.0.1", "*.vercel.app"]
        )

def register_routes(app: FastAPI):
    """Register all application routes."""
    
    # Health check endpoint
    @app.get("/api/health", include_in_schema=False)
    async def health_check():
        """Health check endpoint."""
        try:
            # Check database connection
            async with AsyncSessionLocal() as db:
                await db.execute("SELECT 1")
            
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": settings.VERSION,
                "services": {
                    "database": "healthy",
                    "sniffer": "running" if sniffer and sniffer_service and sniffer_service.is_running else "stopped",
                    "monitor": "running" if monitor else "stopped",
                    "ips": "running" if ips else "stopped"
                }
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=503, detail="Service unhealthy")
    
    # API routes
    app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(user_router.router, prefix="/api/users", tags=["Users"])
    app.include_router(network_router.router, prefix="/api/network", tags=["Network"])
    app.include_router(threat_router.router, prefix="/api/threats", tags=["Threats"])
    app.include_router(system_router.router, prefix="/api/system", tags=["System"])
    app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])
    app.include_router(api_v1_router, prefix="/api/v1", tags=["API v1"])
    app.include_router(ml_models_router.router, prefix="/api/v1/models", tags=["ML Models"])
    
    # Service API routes
    app.include_router(firewall_router, prefix="/api/firewall", tags=["Firewall"])
    app.include_router(intel_router, prefix="/api/intel", tags=["Threat Intelligence"])
    app.include_router(nac_router, prefix="/api/nac", tags=["Network Access Control"])
    app.include_router(dns_router, prefix="/api/dns", tags=["DNS"])
    app.include_router(ml_models_api_router, prefix="/api/ml", tags=["Machine Learning"])

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        shutdown_event.set()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

# Socket.IO events
@sio.event
async def connect(sid, environ):
    """Handle client connection."""
    logger.info(f"Client connected: {sid[:8]}...")
    try:
        interfaces = get_if_list()
        await sio.emit("interfaces", interfaces, to=sid)
        await sio.emit("connection_status", {"status": "connected"}, to=sid)
    except Exception as e:
        logger.error(f"Error handling connection: {e}")

@sio.event
async def disconnect(sid):
    """Handle client disconnection."""
    logger.info(f"Client disconnected: {sid[:8]}...")

@sio.on("start_sniffing")
async def _on_start_sniffing(sid, data):
    """Handle start sniffing request."""
    logger.info(f"User started sniffing on {data.get('sniffingInterface')}")
    global sniffer, sniffer_service
    
    try:
        interface = data.get("sniffingInterface", "Wi-Fi")
        
        if sniffer_service and not sniffer_service.is_running:
            await sniffer_service.start()
        
        if sniffer:
            await sniffer.start(interface)
            await sio.emit("sniffing_started", {"interface": interface}, to=sid)
        else:
            raise Exception("Sniffer not initialized")
            
    except Exception as e:
        logger.error(f"Error starting sniffer: {str(e)}")
        await sio.emit("sniffing_error", {"error": str(e)}, to=sid)

@sio.on("stop_sniffing")
async def _on_stop_sniffing(sid):
    """Handle stop sniffing request."""
    logger.info("User stopped sniffing")
    global sniffer, sniffer_service
    
    try:
        if sniffer:
            sniffer.stop()
            logger.info("PacketSniffer stopped")
        
        if sniffer_service:
            await sniffer_service.stop()
            logger.info("PacketSnifferService stopped")
        
        await sio.emit("sniffing_stopped", to=sid)
        
    except Exception as e:
        logger.error(f"Error stopping sniffer: {str(e)}")
        await sio.emit("sniffing_error", {"error": str(e)}, to=sid)

@sio.on("request_daily_summary")
async def _on_request_summary(sid):
    """Handle daily summary request."""
    try:
        if monitor and not monitor.data_queue.empty():
            stats = monitor.data_queue.get_nowait()
            net24 = get_24h_network_traffic(stats)
            threats = get_daily_threat_summary(monitor)
            await sio.emit(
                "daily_summary",
                {"network24h": net24, "threatSummary": threats},
                to=sid,
            )
    except Empty:
        await sio.emit("daily_summary", {"error": "No data available"}, to=sid)
    except Exception as e:
        logger.error(f"Error getting daily summary: {e}")
        await sio.emit("daily_summary", {"error": "Failed to get summary"}, to=sid)

async def emit_startup_progress():
    """Emit startup progress to connected clients."""
    while not server_ready_emitted and not shutdown_event.is_set():
        elapsed = time.time() - startup_start_time
        await sio.emit("startup_progress", {"elapsed_time": elapsed})
        await asyncio.sleep(0.5)

async def mark_server_ready():
    """Mark server as ready and emit to clients."""
    global server_ready_emitted
    total_time = time.time() - startup_start_time
    await sio.emit("server_ready", {"startup_time": total_time}, namespace="/packet_sniffer")
    server_ready_emitted = True
    logger.info(f"Server ready in {total_time:.2f} seconds")

# Application entry point
async def run_server():
    """Run the server with proper configuration."""
    import hypercorn.asyncio
    from hypercorn.config import Config
    
    config = Config()
    
    # Server binding configuration
    if settings.PRODUCTION:
        config.bind = ["0.0.0.0:8000"]  # Bind to all interfaces in production
    else:
        config.bind = ["0.0.0.0:8000"]  # Also bind to all interfaces in development for external access
    
    config.workers = 1  # Single worker for Socket.IO compatibility
    config.worker_class = "asyncio"
    config.keepalive_timeout = 120
    config.access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
    config.accesslog = "logs/access.log" if not settings.DEBUG else "-"
    config.errorlog = "logs/error.log" if not settings.DEBUG else "-"
    
    # Create application
    app = await create_app()
    
    # Start progress emission
    asyncio.create_task(emit_startup_progress())
    
    # Start server
    logger.info(f"Starting server on {config.bind[0]}")
    await hypercorn.asyncio.serve(app, config, shutdown_trigger=shutdown_event.wait)
    
    # Mark server as ready
    await mark_server_ready()

if __name__ == "__main__":
    try:
        # Create logs directory
        os.makedirs("logs", exist_ok=True)
        
        # Run the server
        asyncio.run(run_server())
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.critical(f"Server failed to start: {e}")
        sys.exit(1)

