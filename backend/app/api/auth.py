# Fixed auth.py with proper authentication handling and rate limiting

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import pyotp
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from typing import Dict, Optional
import time
from collections import defaultdict

from ..core.security import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    get_current_user_for_2fa,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from ..schemas.user import UserInDB
from ..schemas.token import Token
from ..schemas.auth import TwoFactorVerify
from ..database import get_db
from ..models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

# Simple rate limiting (in production, use Redis)
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes

def check_rate_limit(client_ip: str) -> bool:
    """Check if client IP is rate limited."""
    now = time.time()
    # Clean old attempts
    login_attempts[client_ip] = [
        attempt for attempt in login_attempts[client_ip] 
        if now - attempt < LOCKOUT_DURATION
    ]
    
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return False
    return True

def record_login_attempt(client_ip: str):
    """Record a login attempt."""
    login_attempts[client_ip].append(time.time())

@router.post("/login")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login endpoint with rate limiting and proper error handling."""
    client_ip = request.client.host
    
    # Check rate limiting
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )
    
    # Record login attempt
    record_login_attempt(client_ip)
    
    try:
        user = await authenticate_user(db, form_data.username, form_data.password)
        if not user:
            logger.warning(f"Failed login attempt for username: {form_data.username} from IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user account",
            )
        
        # Check if 2FA is enabled
        if user.is_two_factor_enabled and user.two_factor_secret:
            access_token_expires = timedelta(minutes=5)  # Short expiry for 2FA token
            access_token = create_access_token(
                data={
                    "sub": user.username, 
                    "scope": "2fa_required", 
                    "user_id": user.id
                },
                expires_delta=access_token_expires,
            )
            logger.info(f"2FA required for user: {user.username}")
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "is_2fa_required": True,
                "user_id": user.id,
                "expires_in": 300,  # 5 minutes
            }
        else:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user.username, "user_id": user.id},
                expires_delta=access_token_expires,
            )
            logger.info(f"Successful login for user: {user.username}")
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "is_superuser": user.is_superuser,
                }
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login",
        )

@router.post("/verify-2fa", response_model=Token)
async def verify_2fa_login(
    request: Request,
    request_data: TwoFactorVerify,
    current_user: User = Depends(get_current_user_for_2fa),
    db: AsyncSession = Depends(get_db),
):
    """Verify 2FA code and issue full access token."""
    client_ip = request.client.host
    
    try:
        user = await db.get(User, current_user.id)
        if not user or not user.is_two_factor_enabled or not user.two_factor_secret:
            logger.warning(f"2FA verification failed - user not found or 2FA not enabled: {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA not enabled or user not found.",
            )
        
        # Verify TOTP code
        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(request_data.code, valid_window=1):  # Allow 1 window tolerance
            logger.warning(f"Invalid 2FA code for user: {user.username} from IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 2FA code.",
            )
        
        # Issue full access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id},
            expires_delta=access_token_expires
        )
        
        logger.info(f"Successful 2FA verification for user: {user.username}")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during 2FA verification",
        )

@router.get("/me")
async def read_users_me(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user information."""
    try:
        return {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "is_active": current_user.is_active,
            "is_superuser": current_user.is_superuser,
            "is_two_factor_enabled": current_user.is_two_factor_enabled,
            "created_at": current_user.created_at,
            "updated_at": current_user.updated_at,
        }
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user information",
        )

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
):
    """Logout endpoint (token invalidation would require Redis/database)."""
    logger.info(f"User logged out: {current_user.username}")
    return {"message": "Successfully logged out"}

@router.post("/refresh")
async def refresh_token(
    current_user: User = Depends(get_current_active_user),
):
    """Refresh access token."""
    try:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": current_user.username, "user_id": current_user.id},
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error refreshing token",
        )

