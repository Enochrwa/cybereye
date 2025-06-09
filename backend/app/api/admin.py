# backend/app/api/admin.py
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession # Changed from sqlalchemy.orm import Session
from ..services.database.autofill import DatabaseAutofiller # Adjusted import path
from ..database import get_db # Adjusted import path

from ..core.security import get_current_active_user # Import authentication dependency
from ..models.user import User # Import User model for type hinting

router = APIRouter()


@router.post("/autofill", tags=["Admin"])
async def trigger_autofill( # Changed to async def
    count: int = 10, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # Note: DatabaseAutofiller and its methods are likely synchronous.
    # If this endpoint becomes heavily used, consider running filler.autofill_all 
    # in a threadpool: await run_in_threadpool(filler.autofill_all, count=count)
    # For now, direct call is fine for an admin endpoint not expected to be high-traffic.
    filler = DatabaseAutofiller(db) 
    results = filler.autofill_all(count=count) # This might block if it's purely sync DB IO with AsyncSession
    return {"message": f"Added {len(results)} records", "details": results}
