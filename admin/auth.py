"""Authentication module for admin panel."""
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

logger = logging.getLogger(__name__)

# Security settings
SECRET_KEY = "your-secret-key-change-in-production-use-environment-variable"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token.
    
    Args:
        data: Data to encode in token
        expires_delta: Token expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token and return username.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        Username from token
        
    Raises:
        HTTPException: If token is invalid
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
        
        return username
        
    except JWTError:
        raise credentials_exception


async def authenticate_user(
    username: str,
    password: str,
    db_manager
) -> Optional[dict]:
    """Authenticate user.
    
    Args:
        username: Username
        password: Plain text password
        db_manager: Database manager instance
        
    Returns:
        User data if authenticated, None otherwise
    """
    user = await db_manager.get_admin_user(username)
    
    if not user:
        logger.warning(f"Authentication attempt with unknown username: {username}")
        return None
    
    # Simple direct password comparison (for development/demo purposes)
    # In production, use hashed passwords with verify_password()
    stored_password = user.get('password_hash') or user.get('password', '')
    
    # If stored password is a hash (starts with $2b$), verify it
    if stored_password.startswith('$2b$'):
        if not verify_password(password, stored_password):
            logger.warning(f"Authentication failed for user: {username}")
            return None
    else:
        # Direct password comparison
        if password != stored_password:
            logger.warning(f"Authentication failed for user: {username}")
            return None
    
    logger.info(f"User authenticated: {username}")
    return user


async def get_current_admin(
    request: Request,
    username: str = Depends(verify_token)
) -> dict:
    """Get current admin user.
    
    Args:
        request: FastAPI request
        username: Username from token
        
    Returns:
        Admin user data
    """
    db_manager = request.app.state.db_manager
    user = await db_manager.get_admin_user(username)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

