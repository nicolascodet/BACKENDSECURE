import os
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from google.auth.transport import requests
from google.oauth2 import id_token

from ...core.security import (
    create_access_token, 
    verify_password, 
    get_password_hash,
    generate_api_key,
    generate_reset_token
)
from ...core.auth import get_current_user, get_current_active_user
from ...core.middleware import limiter
from ...core.database import user_db, create_user_mock, get_user_by_email_mock, MOCK_USERS
from ...schemas.user import (
    UserCreate, 
    UserLogin, 
    UserResponse, 
    Token, 
    PasswordReset,
    PasswordResetConfirm,
    APIKeyResponse,
    GoogleTokenRequest
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Mock storage for demo
mock_api_keys_db = {}
mock_reset_tokens = {}

@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def register(request: Request, user_data: UserCreate):
    """Register a new user"""
    
    # Check if user already exists
    existing_user = await user_db.get_user_by_email(user_data.email)
    if not existing_user:
        existing_user = await get_user_by_email_mock(user_data.email)
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(user_data.password)
    
    new_user_data = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "is_active": True,
        "is_government": user_data.is_government,
        "organization": user_data.organization,
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None
    }
    
    # Try to save to database, fallback to mock
    try:
        new_user = await user_db.create_user(new_user_data)
    except:
        new_user = await create_user_mock(new_user_data)
    
    # Create access token
    access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
    access_token = create_access_token(
        data={"sub": user_data.email, "user_id": user_id},
        expires_delta=access_token_expires
    )
    
    user_response = UserResponse(
        id=user_id,
        email=user_data.email,
        full_name=user_data.full_name,
        is_active=True,
        is_government=user_data.is_government,
        organization=user_data.organization,
        created_at=datetime.fromisoformat(new_user["created_at"].replace("Z", "+00:00")) if isinstance(new_user["created_at"], str) else new_user["created_at"]
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(access_token_expires.total_seconds()),
        user=user_response
    )

@router.post("/login", response_model=Token)
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def login(request: Request, credentials: UserLogin):
    """Login with email and password"""
    
    # Find user in database or mock
    user = await user_db.get_user_by_email(credentials.email)
    if not user:
        user = await get_user_by_email_mock(credentials.email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Verify password
    if not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Update last login
    try:
        await user_db.update_last_login(user["id"])
    except:
        user["last_login"] = datetime.utcnow().isoformat()
    
    # Create access token
    access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
    access_token = create_access_token(
        data={"sub": credentials.email, "user_id": user["id"]},
        expires_delta=access_token_expires
    )
    
    user_response = UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user["full_name"],
        is_active=user["is_active"],
        is_government=user["is_government"],
        organization=user["organization"],
        created_at=datetime.fromisoformat(user["created_at"].replace("Z", "+00:00")) if isinstance(user["created_at"], str) else user["created_at"],
        last_login=datetime.fromisoformat(user["last_login"].replace("Z", "+00:00")) if user.get("last_login") and isinstance(user["last_login"], str) else user.get("last_login")
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(access_token_expires.total_seconds()),
        user=user_response
    )

@router.post("/google", response_model=Token)
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def google_login(request: Request, token_request: GoogleTokenRequest):
    """Login with Google OAuth token"""
    try:
        # Verify Google token
        idinfo = id_token.verify_oauth2_token(
            token_request.token, 
            requests.Request(), 
            os.getenv("GOOGLE_CLIENT_ID")
        )
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        email = idinfo['email']
        name = idinfo.get('name', '')
        
        # Check if user exists
        user = await user_db.get_user_by_email(email)
        if not user:
            user = await get_user_by_email_mock(email)
        
        if not user:
            # Create new OAuth user
            user_id = str(uuid.uuid4())
            user_data = {
                "id": user_id,
                "email": email,
                "full_name": name,
                "hashed_password": None,  # OAuth user
                "is_active": True,
                "is_government": False,
                "organization": None,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            
            try:
                user = await user_db.create_user(user_data)
            except:
                user = await create_user_mock(user_data)
        else:
            # Update last login
            try:
                await user_db.update_last_login(user["id"])
            except:
                user["last_login"] = datetime.utcnow().isoformat()
        
        # Create access token
        access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
        access_token = create_access_token(
            data={"sub": email, "user_id": user["id"]},
            expires_delta=access_token_expires
        )
        
        user_response = UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user["full_name"],
            is_active=user["is_active"],
            is_government=user["is_government"],
            organization=user["organization"],
            created_at=datetime.fromisoformat(user["created_at"].replace("Z", "+00:00")) if isinstance(user["created_at"], str) else user["created_at"],
            last_login=datetime.fromisoformat(user["last_login"].replace("Z", "+00:00")) if user.get("last_login") and isinstance(user["last_login"], str) else user.get("last_login")
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            user=user_response
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_active_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        is_active=current_user["is_active"],
        is_government=current_user["is_government"],
        organization=current_user["organization"],
        created_at=datetime.fromisoformat(current_user["created_at"].replace("Z", "+00:00")) if isinstance(current_user["created_at"], str) else current_user["created_at"],
        last_login=datetime.fromisoformat(current_user["last_login"].replace("Z", "+00:00")) if current_user.get("last_login") and isinstance(current_user["last_login"], str) else current_user.get("last_login")
    )

@router.post("/api-key", response_model=APIKeyResponse)
async def create_api_key(
    description: str = "API Key", 
    current_user: dict = Depends(get_current_active_user)
):
    """Create a new API key for the current user"""
    api_key = generate_api_key()
    key_data = {
        "api_key": api_key,
        "user_id": current_user["id"],
        "description": description,
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    
    mock_api_keys_db[api_key] = key_data
    
    return APIKeyResponse(
        api_key=api_key,
        created_at=key_data["created_at"],
        description=description
    )

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user (in a real app, you'd invalidate the token)"""
    return {"message": "Successfully logged out"}

@router.post("/forgot-password")
@limiter.limit("5/minute")  # Stricter rate limit for password reset
async def forgot_password(request: Request, password_reset: PasswordReset):
    """Request password reset"""
    user = await user_db.get_user_by_email(password_reset.email)
    if not user:
        user = await get_user_by_email_mock(password_reset.email)
    
    if not user:
        # Don't reveal if email exists
        return {"message": "If the email exists, a reset link has been sent"}
    
    reset_token = generate_reset_token()
    mock_reset_tokens[reset_token] = {
        "email": password_reset.email,
        "expires": datetime.utcnow() + timedelta(hours=1)
    }
    
    # In production, send email with reset link
    print(f"Password reset token for {password_reset.email}: {reset_token}")
    
    return {"message": "If the email exists, a reset link has been sent"}
