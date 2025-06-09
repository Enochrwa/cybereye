from fastapi import APIRouter, Depends # Added Depends
from pydantic import BaseModel

from ....core.security import get_current_active_user # Import auth dependency
from ....models.user import User # Import User model

router = APIRouter()


class GeneralSettings(BaseModel):
    notification_email: str
    update_frequency: str
    data_retention_days: int


@router.get("/general", response_model=GeneralSettings)
async def get_general_settings(current_user: User = Depends(get_current_active_user)):
    """
    Retrieve mock general system settings.
    """
    return GeneralSettings(
        notification_email="admin@ecyber.com",
        update_frequency="daily",
        data_retention_days=90,
    )
