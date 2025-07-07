import os
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .security import verify_token, extract_token_from_header
from .database import user_db, token_blacklist, log_audit_event
from ..schemas.user import TokenData

security = HTTPBearer()

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get current authenticated user from JWT token with security checks"""
    token = credentials.credentials
    
    # Check if token is blacklisted
    if token_blacklist.is_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload = verify_token(token)
        email: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        
        if email is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Get user from database
        user = await user_db.get_user_by_id(user_id)
        if not user:
            # Fallback to mock user for demo
            user = {
                "id": user_id,
                "email": email,
                "full_name": "Demo User",
                "is_active": True,
                "is_government": False,
                "organization": None,
                "created_at": "2024-01-01T00:00:00",
                "last_login": None
            }
        
        # Log successful authentication
        await log_audit_event(
            user_id=user_id,
            action="token_validation",
            endpoint=str(request.url),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        
        return user
        
    except Exception as e:
        # Log failed authentication attempt
        await log_audit_event(
            user_id="unknown",
            action="failed_token_validation",
            endpoint=str(request.url),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_active_user(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Get current active user (must be active)"""
    if not current_user.get("is_active"):
        # Log inactive user access attempt
        await log_audit_event(
            user_id=current_user["id"],
            action="inactive_user_access_attempt",
            endpoint=str(request.url),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

async def get_government_user(
    request: Request,
    current_user: dict = Depends(get_current_active_user)
):
    """Get current user (must be government user)"""
    if not current_user.get("is_government"):
        # Log unauthorized government access attempt
        await log_audit_event(
            user_id=current_user["id"],
            action="unauthorized_government_access",
            endpoint=str(request.url),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"user_type": "civilian", "attempted_endpoint": str(request.url)}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Government access required."
        )
    
    # Log successful government access
    await log_audit_event(
        user_id=current_user["id"],
        action="government_access_granted",
        endpoint=str(request.url),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return current_user

async def revoke_token(token: str, user_id: str, request: Request):
    """Revoke a token by adding it to blacklist"""
    token_blacklist.blacklist_token(token)
    
    # Log token revocation
    await log_audit_event(
        user_id=user_id,
        action="token_revoked",
        endpoint=str(request.url),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"reason": "user_logout"}
    )
