import os
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List

from ...core.auth import get_current_user, get_current_active_user, get_government_user
from ...core.middleware import limiter
from ...core.database import log_audit_event
from ...schemas.user import UserResponse

router = APIRouter(prefix="/protected", tags=["Protected Endpoints"])

@router.get("/profile", response_model=UserResponse)
async def get_profile(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Get user profile (requires authentication)"""
    from datetime import datetime
    
    # Log profile access
    await log_audit_event(
        user_id=current_user["id"],
        action="profile_accessed",
        endpoint="/protected/profile",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
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

@router.get("/dashboard")
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def dashboard(request: Request, current_user: dict = Depends(get_current_active_user)):
    """User dashboard (requires authentication)"""
    
    # Log dashboard access
    await log_audit_event(
        user_id=current_user["id"],
        action="dashboard_accessed",
        endpoint="/protected/dashboard",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {
        "message": f"Welcome to your dashboard, {current_user['email']}!",
        "user_type": "Government User" if current_user["is_government"] else "Regular User",
        "organization": current_user.get("organization", "None"),
        "stats": {
            "emails_processed": 0,
            "contracts_monitored": 0,
            "last_login": current_user.get("last_login"),
            "account_created": current_user.get("created_at")
        },
        "features": {
            "email_monitoring": "Available",
            "contract_analysis": "Available",
            "government_access": current_user["is_government"]
        }
    }

@router.get("/government-only")
async def government_only(request: Request, current_user: dict = Depends(get_government_user)):
    """Government users only endpoint"""
    return {
        "message": "This is classified government information",
        "user": current_user["email"],
        "clearance_level": "CONFIDENTIAL",
        "accessible_systems": [
            "GSA eBuy",
            "SAM.gov",
            "FPDS-NG",
            "Contract Opportunities",
            "FedBizOpps"
        ],
        "contract_data": {
            "total_opportunities": 1247,
            "new_today": 23,
            "matching_keywords": 8,
            "relevant_agencies": ["DOD", "GSA", "DHS", "VA"]
        }
    }

@router.get("/admin")
async def admin_endpoint(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Admin endpoint (could add admin role check)"""
    
    # Log admin access attempt
    await log_audit_event(
        user_id=current_user["id"],
        action="admin_panel_accessed",
        endpoint="/protected/admin",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    # In production, add admin role verification
    return {
        "message": "Admin panel access",
        "system_status": "operational",
        "active_users": 1,
        "total_contracts_monitored": 0,
        "system_uptime": "99.9%",
        "security": {
            "failed_login_attempts": 0,
            "active_sessions": 1,
            "api_calls_today": 15
        }
    }

@router.get("/api-usage")
@limiter.limit("10/minute")  # Lower rate limit for usage stats
async def api_usage(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Get API usage statistics"""
    
    # Log API usage stats access
    await log_audit_event(
        user_id=current_user["id"],
        action="api_usage_viewed",
        endpoint="/protected/api-usage",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {
        "user_id": current_user["id"],
        "api_calls_today": 0,
        "api_calls_this_month": 0,
        "rate_limit": f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute",
        "quota_remaining": "100%",
        "last_api_call": None,
        "endpoints_accessed": [
            "/auth/me",
            "/protected/dashboard",
            "/protected/profile"
        ]
    }

@router.get("/contracts")
@limiter.limit(f"{os.getenv('RATE_LIMIT_PER_MINUTE', '100')}/minute")
async def get_contracts(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Get user's contract monitoring data"""
    
    # Log contract data access
    await log_audit_event(
        user_id=current_user["id"],
        action="contract_data_accessed",
        endpoint="/protected/contracts",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {
        "message": "Contract monitoring system",
        "user": current_user["email"],
        "contracts": {
            "active_monitors": 0,
            "new_opportunities": 0,
            "expiring_soon": 0,
            "total_value": "$0"
        },
        "alerts": [],
        "keywords": [],
        "agencies": []
    }

@router.post("/contracts/monitor")
async def create_contract_monitor(
    request: Request,
    keywords: List[str],
    agencies: List[str] = [],
    current_user: dict = Depends(get_current_active_user)
):
    """Create a new contract monitoring alert"""
    
    # Log contract monitor creation
    await log_audit_event(
        user_id=current_user["id"],
        action="contract_monitor_created",
        endpoint="/protected/contracts/monitor",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={
            "keywords": keywords,
            "agencies": agencies
        }
    )
    
    return {
        "message": "Contract monitor created successfully",
        "monitor_id": "monitor_123",
        "keywords": keywords,
        "agencies": agencies,
        "user_id": current_user["id"],
        "status": "active"
    }

@router.get("/audit-logs")
@limiter.limit("20/minute")  # Limited rate for audit log access
async def get_user_audit_logs(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Get current user's audit logs"""
    from ...core.database import audit_log_db
    
    # Log audit log access
    await log_audit_event(
        user_id=current_user["id"],
        action="audit_logs_accessed",
        endpoint="/protected/audit-logs",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    # Get user's audit logs
    logs = await audit_log_db.get_audit_logs(user_id=current_user["id"], limit=50)
    
    return {
        "message": "User audit logs",
        "user_id": current_user["id"],
        "total_logs": len(logs),
        "logs": logs
    }
