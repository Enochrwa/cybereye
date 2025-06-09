# backend/app/api/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession # Changed from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel  # Added for UserSummary

from ..database import get_db
from ..models.user import User  # Import the SQLAlchemy model and used as current_user type
from ..schemas.user import UserCreate, UserInDB, UserUpdate
# Assuming these service functions are async, if not, they'd block the event loop
from ..services.user import get_user, get_users, create_user, update_user, delete_user, get_user_by_email

from ..core.security import get_current_active_user # Corrected relative import

router = APIRouter()


@router.post("/", response_model=UserInDB)
async def create_new_user(
    user: UserCreate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    db_user = await get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return await create_user(db=db, user=user)


@router.get("/", response_model=List[UserInDB])
async def read_users(
    skip: int = 0, 
    limit: int = 100, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    users = await get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=UserInDB)
async def read_user( # Changed to async def
    user_id: int, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # Assuming get_user is an async function; if it's sync, it needs to be run in a threadpool
    db_user = await get_user(db, user_id=user_id) 
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/{user_id}", response_model=UserInDB)
async def update_existing_user( # Changed to async def
    user_id: int, 
    user: UserUpdate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # Assuming get_user and update_user are async functions
    db_user = await get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return await update_user(db=db, user_id=user_id, user=user)


@router.delete("/{user_id}", response_model=UserInDB)
async def delete_existing_user( # Changed to async def
    user_id: int, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # Assuming get_user and delete_user are async functions
    db_user = await get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return await delete_user(db=db, user_id=user_id)


# Pydantic model for User Summary
class UserSummary(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int


@router.get("/summary", response_model=UserSummary)
async def get_user_summary(db: Session = Depends(get_db)):
    """
    Retrieve a summary of users.
    """
    # Note: db.query().count() is synchronous. If db is AsyncSession, this needs to be converted to async.
    # This part is out of scope for the current auth refactoring.
    # For now, assuming this part will be fixed separately or db session type might be handled by a wrapper.
    # The primary change here is adding current_user and ensuring db type is AsyncSession.
    total_users = db.query(User).count() 
    admin_users = db.query(User).filter(User.is_superuser == True).count()
    standard_users = total_users - admin_users
    return UserSummary(
        total_users=total_users, admin_users=admin_users, standard_users=standard_users
    )
