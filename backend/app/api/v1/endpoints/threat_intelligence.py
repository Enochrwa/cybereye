from fastapi import APIRouter, HTTPException, Depends
from ....services.threat_intelligence_service import ThreatIntelligenceService
from ....models.user import User # Import User model
from ....core.security import get_current_active_user # Import auth dependency
from pydantic import BaseModel
from typing import List, Optional, Any

router = APIRouter()

# Dependency provider for ThreatIntelligenceService
_threat_intel_service_instance: Optional[ThreatIntelligenceService] = None
_threat_intel_service_initialized: bool = False

async def get_threat_intel_service() -> ThreatIntelligenceService: # Changed to async def
    global _threat_intel_service_instance, _threat_intel_service_initialized
    
    if _threat_intel_service_instance is None:
        _threat_intel_service_instance = ThreatIntelligenceService() # Synchronous instantiation
    
    if not _threat_intel_service_initialized:
        if _threat_intel_service_instance: # Should always be true here
            await _threat_intel_service_instance.initial_data_load()
            _threat_intel_service_initialized = True
        else:
            # This case should ideally not be reached if instance is created above.
            # Handling for robustness, though it might indicate a logic error if ever hit.
            raise HTTPException(status_code=500, detail="Threat intelligence service not available.")

    if _threat_intel_service_instance is None: # Defensive check, should not happen
        raise HTTPException(status_code=500, detail="Threat intelligence service failed to initialize.")
        
    return _threat_intel_service_instance

# Pydantic Models for API responses
class FeedStatus(BaseModel):
    id: str
    name: str
    status: str
    entries: int
    last_updated: Optional[str] = None
    source_url: Optional[str] = None
    is_subscribed: (
        bool  # Ensure this is not optional or defaulted here for clarity in response.
    )


class EmergingThreat(BaseModel):
    type: str
    id: Optional[str] = None
    summary: Optional[str] = None
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    threat_type: Optional[str] = None
    source: str
    published: Optional[str] = None
    last_seen: Optional[str] = None


class SubscriptionResponse(BaseModel):
    feed_id: str
    subscribed: bool  # Renamed from is_subscribed to match service logic return key


class SubscriptionRequest(BaseModel):
    is_subscribed: bool


class RefreshResponse(BaseModel):
    feed_id: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    message: Optional[str] = None
    last_updated: Optional[str] = None
    entry_count: Optional[int] = None


@router.get("/emerging-threats", response_model=List[EmergingThreat])
async def get_emerging_threats_endpoint(service: ThreatIntelligenceService = Depends(get_threat_intel_service)):
    try:
        return service.get_emerging_threats()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get emerging threats: {str(e)}"
        )


@router.get("/feeds", response_model=List[FeedStatus])
async def list_feeds_endpoint(service: ThreatIntelligenceService = Depends(get_threat_intel_service)):
    try:
        return service.get_feeds()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list feeds: {str(e)}")


# Use response_model=FeedStatus for subscribe endpoint as service returns the updated feed status
@router.post("/feeds/{feed_id}/subscribe", response_model=FeedStatus)
async def subscribe_to_feed_endpoint(
    feed_id: str,
    subscription_request: SubscriptionRequest,
    service: ThreatIntelligenceService = Depends(get_threat_intel_service),
    current_user: User = Depends(get_current_active_user)
):
    try:
        # The service method now returns the updated feed status or an error dict
        result = service.update_feed_subscription(
            feed_id, subscription_request.is_subscribed
        )
        if isinstance(result, dict) and "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        # Ensure the result matches the FeedStatus model
        # The service's get_feeds() and update_feed_subscription() should be consistent
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        # logger.error(f"Error in subscribe_to_feed_endpoint for {feed_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update subscription for feed {feed_id}: {str(e)}",
        )


@router.post("/feeds/{feed_id}/refresh", response_model=RefreshResponse)
async def refresh_feed_endpoint(
    feed_id: str, 
    service: ThreatIntelligenceService = Depends(get_threat_intel_service),
    current_user: User = Depends(get_current_active_user)
):
    try:
        result = service.refresh_feed_data(feed_id)
        # Result is a dictionary like:
        # {"feed_id": feed_id, "status": "refreshed", "last_updated": last_updated_ts, "entry_count": ...}
        # OR {"feed_id": feed_id, "status": "error", "error": ...}
        # OR {"feed_id": feed_id, "status": "skipped", "message": ...}

        if result.get("status") == "error":
            if "not recognized" in result.get("error", ""):
                raise HTTPException(status_code=404, detail=result.get("error"))
            return RefreshResponse(**result)  # Map directly if keys match
        elif result.get("status") == "skipped":
            return RefreshResponse(
                feed_id=feed_id,
                status="skipped",
                message=result.get("message", "Skipped for unspecified reason"),
            )
        elif result.get("status") == "refreshed":
            return RefreshResponse(
                feed_id=feed_id,
                status="refreshed",
                message=f"Feed '{feed_id}' data refreshed successfully.",
                last_updated=result.get("last_updated"),
                entry_count=result.get("entry_count"),
            )
        # Fallback for unexpected result structure
        return RefreshResponse(
            feed_id=feed_id,
            status="unknown",
            error="Unknown result from refresh operation",
        )

    except HTTPException as http_exc:  # Re-raise HTTP exceptions
        raise http_exc
    except Exception as e:
        # logger.error(f"Unhandled exception in refresh_feed_endpoint for {feed_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred while refreshing feed {feed_id}: {str(e)}",
        )
