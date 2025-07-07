import os
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from google.auth.transport import requests
from google.oauth2 import id_token

from ...core.security import (
    create_access_token, 
    create_refresh_token,
    verify_refresh_token,
    verify_password, 
    get_password_hash,
    generate_api_key,
    generate_reset_token,
    validate_password_strength
)
from ...core.auth import get_current_user, get_current_active_user, revoke_token
from ...core.middleware import limiter
from ...core.database import (
    user_db, 
    refresh_token_db,
    create_user_mock, 
    get_user_by_email_mock, 
    MOCK_USERS,
    log_audit_event
)
from ...schemas.user import (
    UserCreate, 
    UserLogin, 
    UserResponse, 
    Token, 
    RefreshTokenRequest,
    RefreshTokenResponse,
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
    """Register a new user with enhanced security"""
    
    # Validate password strength
    if not validate_password_strength(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least 8 characters with uppercase, lowercase, numbers, and special characters"
        )
    
    # Check if user already exists
    existing_user = await user_db.get_user_by_email(user_data.email)
    if not existing_user:
        existing_user = await get_user_by_email_mock(user_data.email)
    
    if existing_user:
        # Log registration attempt with existing email
        await log_audit_event(
            user_id="unknown",
            action="registration_attempt_existing_email",
            endpoint="/auth/register",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": user_data.email}
        )
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
    
    # Create access and refresh tokens
    access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
    refresh_token_expires = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_DAYS", "7")))
    
    access_token = create_access_token(
        data={"sub": user_data.email, "user_id": user_id},
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        data={"sub": user_data.email, "user_id": user_id}
    )
    
    # Store refresh token
    await refresh_token_db.create_refresh_token(
        user_id=user_id,
        token=refresh_token,
        expires_at=datetime.utcnow() + refresh_token_expires
    )
    
    # Log successful registration
    await log_audit_event(
        user_id=user_id,
        action="user_registered",
        endpoint="/auth/register",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={
            "email": user_data.email,
            "is_government": user_data.is_government,
            "organization": user_data.organization
        }
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
        refresh_token=refresh_token,
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
        # Log failed login attempt
        await log_audit_event(
            user_id="unknown",
            action="login_failed_user_not_found",
            endpoint="/auth/login",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": credentials.email}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Verify password
    if not verify_password(credentials.password, user["hashed_password"]):
        # Log failed login attempt
        await log_audit_event(
            user_id=user["id"],
            action="login_failed_wrong_password",
            endpoint="/auth/login",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": credentials.email}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user["is_active"]:
        # Log inactive user login attempt
        await log_audit_event(
            user_id=user["id"],
            action="login_failed_inactive_user",
            endpoint="/auth/login",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": credentials.email}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Update last login
    try:
        await user_db.update_last_login(user["id"])
    except:
        user["last_login"] = datetime.utcnow().isoformat()
    
    # Create access and refresh tokens
    access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
    refresh_token_expires = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_DAYS", "7")))
    
    access_token = create_access_token(
        data={"sub": credentials.email, "user_id": user["id"]},
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        data={"sub": credentials.email, "user_id": user["id"]}
    )
    
    # Store refresh token
    await refresh_token_db.create_refresh_token(
        user_id=user["id"],
        token=refresh_token,
        expires_at=datetime.utcnow() + refresh_token_expires
    )
    
    # Log successful login
    await log_audit_event(
        user_id=user["id"],
        action="user_logged_in",
        endpoint="/auth/login",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"email": credentials.email}
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
        refresh_token=refresh_token,
        user=user_response
    )

@router.post("/refresh-token", response_model=RefreshTokenResponse)
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def refresh_access_token(request: Request, refresh_request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    
    try:
        # Verify refresh token
        payload = verify_refresh_token(refresh_request.refresh_token)
        email = payload.get("sub")
        user_id = payload.get("user_id")
        
        if not email or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Check if refresh token exists in database
        stored_token = await refresh_token_db.get_refresh_token(refresh_request.refresh_token)
        if not stored_token or not stored_token.get("is_active"):
            # Log invalid refresh token attempt
            await log_audit_event(
                user_id=user_id,
                action="refresh_token_invalid",
                endpoint="/auth/refresh-token",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Check if token is expired
        expires_at = datetime.fromisoformat(stored_token["expires_at"].replace("Z", "+00:00"))
        if datetime.utcnow() > expires_at:
            # Invalidate expired token
            await refresh_token_db.invalidate_refresh_token(refresh_request.refresh_token)
            
            await log_audit_event(
                user_id=user_id,
                action="refresh_token_expired",
                endpoint="/auth/refresh-token",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        
        # Get user to ensure they still exist and are active
        user = await user_db.get_user_by_id(user_id)
        if not user:
            user = await get_user_by_email_mock(email)
        
        if not user or not user.get("is_active"):
            await log_audit_event(
                user_id=user_id,
                action="refresh_token_user_inactive",
                endpoint="/auth/refresh-token",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new tokens
        access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
        refresh_token_expires = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_DAYS", "7")))
        
        new_access_token = create_access_token(
            data={"sub": email, "user_id": user_id},
            expires_delta=access_token_expires
        )
        
        new_refresh_token = create_refresh_token(
            data={"sub": email, "user_id": user_id}
        )
        
        # Invalidate old refresh token
        await refresh_token_db.invalidate_refresh_token(refresh_request.refresh_token)
        
        # Store new refresh token
        await refresh_token_db.create_refresh_token(
            user_id=user_id,
            token=new_refresh_token,
            expires_at=datetime.utcnow() + refresh_token_expires
        )
        
        # Log successful token refresh
        await log_audit_event(
            user_id=user_id,
            action="token_refreshed",
            endpoint="/auth/refresh-token",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        
        return RefreshTokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds())
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await log_audit_event(
            user_id="unknown",
            action="refresh_token_error",
            endpoint="/auth/refresh-token",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not refresh token"
        )

@router.post("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    """Logout user and revoke tokens"""
    
    # Get the token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.replace("Bearer ", "")
        await revoke_token(token, current_user["id"], request)
    
    # Log logout
    await log_audit_event(
        user_id=current_user["id"],
        action="user_logged_out",
        endpoint="/auth/logout",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {"message": "Successfully logged out"}

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
                
            # Log new OAuth user creation
            await log_audit_event(
                user_id=user_id,
                action="oauth_user_created",
                endpoint="/auth/google",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                details={"email": email, "provider": "google"}
            )
        else:
            # Update last login
            try:
                await user_db.update_last_login(user["id"])
            except:
                user["last_login"] = datetime.utcnow().isoformat()
        
        # Create access and refresh tokens
        access_token_expires = timedelta(hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
        refresh_token_expires = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_DAYS", "7")))
        
        access_token = create_access_token(
            data={"sub": email, "user_id": user["id"]},
            expires_delta=access_token_expires
        )
        
        refresh_token = create_refresh_token(
            data={"sub": email, "user_id": user["id"]}
        )
        
        # Store refresh token
        await refresh_token_db.create_refresh_token(
            user_id=user["id"],
            token=refresh_token,
            expires_at=datetime.utcnow() + refresh_token_expires
        )
        
        # Log successful OAuth login
        await log_audit_event(
            user_id=user["id"],
            action="oauth_login_success",
            endpoint="/auth/google",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": email, "provider": "google"}
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
            refresh_token=refresh_token,
            user=user_response
        )
        
    except ValueError as e:
        await log_audit_event(
            user_id="unknown",
            action="oauth_login_failed",
            endpoint="/auth/google",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"error": str(e), "provider": "google"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(request: Request, current_user: dict = Depends(get_current_active_user)):
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
    request: Request,
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
    
    # Log API key creation
    await log_audit_event(
        user_id=current_user["id"],
        action="api_key_created",
        endpoint="/auth/api-key",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"description": description}
    )
    
    return APIKeyResponse(
        api_key=api_key,
        created_at=key_data["created_at"],
        description=description
    )

@router.post("/forgot-password")
@limiter.limit("5/minute")  # Stricter rate limit for password reset
async def forgot_password(request: Request, password_reset: PasswordReset):
    """Request password reset"""
    user = await user_db.get_user_by_email(password_reset.email)
    if not user:
        user = await get_user_by_email_mock(password_reset.email)
    
    if user:
        reset_token = generate_reset_token()
        mock_reset_tokens[reset_token] = {
            "email": password_reset.email,
            "expires": datetime.utcnow() + timedelta(hours=1)
        }
        
        # Log password reset request
        await log_audit_event(
            user_id=user["id"],
            action="password_reset_requested",
            endpoint="/auth/forgot-password",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": password_reset.email}
        )
        
        # In production, send email with reset link
        # TODO: Implement email service to send reset token
    else:
        # Log password reset attempt for non-existent user
        await log_audit_event(
            user_id="unknown",
            action="password_reset_unknown_email",
            endpoint="/auth/forgot-password",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": password_reset.email}
        )
    
    # Don't reveal if email exists
    return {"message": "If the email exists, a reset link has been sent"}

@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, reset_data: PasswordResetConfirm):
    """Reset password with token"""
    token_data = mock_reset_tokens.get(reset_data.token)
    
    if not token_data or datetime.utcnow() > token_data["expires"]:
        await log_audit_event(
            user_id="unknown",
            action="password_reset_invalid_token",
            endpoint="/auth/reset-password",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Validate new password strength
    if not validate_password_strength(reset_data.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least 8 characters with uppercase, lowercase, numbers, and special characters"
        )
    
    # Update password
    email = token_data["email"]
    user = await user_db.get_user_by_email(email)
    if not user:
        user = await get_user_by_email_mock(email)
    
    if user:
        hashed_password = get_password_hash(reset_data.new_password)
        await user_db.update_user(user["id"], {"hashed_password": hashed_password})
        
        # Log successful password reset
        await log_audit_event(
            user_id=user["id"],
            action="password_reset_completed",
            endpoint="/auth/reset-password",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"email": email}
        )
        
        # Remove used token
        del mock_reset_tokens[reset_data.token]
        
        return {"message": "Password reset successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User not found"
    )
