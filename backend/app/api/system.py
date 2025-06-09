from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from ..services.monitoring.sniffer import PacketSniffer # Adjusted import path
from ..core.dependencies import get_packet_sniffer # Adjusted import path
from ..utils.get_system_info import get_system_info, get_network_interfaces # Adjusted import path

from ..core.security import get_current_active_user # Import auth dependency
from ..models.user import User # Import User model

router = APIRouter()


@router.get("/stats", response_model=dict)
async def get_system_stats(
    sniffer: PacketSniffer = Depends(get_packet_sniffer),
    current_user: User = Depends(get_current_active_user)
):
    """Get current system statistics"""
    return sniffer.get_stats()


@router.get("/system_info")
async def system_status(current_user: User = Depends(get_current_active_user)): # Changed to async, added auth
    return get_system_info()

@router.get("/interfaces")
async def get_interfaces(current_user: User = Depends(get_current_active_user)): # Changed to async, added auth
    return get_network_interfaces()
