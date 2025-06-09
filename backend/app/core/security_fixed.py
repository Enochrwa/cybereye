# Fixed security.py with proper authentication handling

from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from ..database import get_db
from ..models.user import User
from ..schemas.user import UserInDB
from ..schemas.token import TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fixed OAuth2 token URL to match the actual endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Use environment variable for secret key with secure fallback
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    import secrets
    SECRET_KEY = secrets.token_urlsafe(32)
    print("WARNING: Using generated SECRET_KEY. Set SECRET_KEY environment variable for production!")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        # Log the error but don't expose it
        import logging
        logging.getLogger(__name__).error(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")
        
        if username is None:
            raise credentials_exception
        
        # Check if token is only for 2FA verification
        if scope == "2fa_required":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token valid only for 2FA verification. Complete 2FA to access resources.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token_data = TokenData(username=username, scope=scope)
    except JWTError as e:
        import logging
        logging.getLogger(__name__).error(f"JWT decode error: {e}")
        raise credentials_exception
    
    try:
        result = await db.execute(select(User).where(User.username == token_data.username))
        user = result.scalars().first()
        if user is None:
            raise credentials_exception
        return user
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Database error in get_current_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    return current_user

async def authenticate_user(
    db: AsyncSession, username: str, password: str
) -> Optional[User]:
    """Authenticate user with username and password."""
    try:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalars().first()
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Authentication error: {e}")
        return None

async def get_current_user_for_2fa(
    token: str = Depends(oauth2_scheme), 
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user for 2FA verification step."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials for 2FA",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")
        user_id: Optional[int] = payload.get("user_id")
        
        if username is None or scope != "2fa_required" or user_id is None:
            raise credentials_exception
            
    except JWTError as e:
        import logging
        logging.getLogger(__name__).error(f"JWT decode error in 2FA: {e}")
        raise credentials_exception
    
    try:
        user = await db.get(User, user_id)
        if user is None or user.username != username:
            raise credentials_exception
        return user
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Database error in get_current_user_for_2fa: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

