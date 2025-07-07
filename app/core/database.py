import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from supabase import create_client, Client
import json

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY"))

if supabase_url and supabase_key:
    supabase: Client = create_client(supabase_url, supabase_key)
else:
    supabase = None

class UserDatabase:
    def __init__(self):
        self.table_name = "users"
        
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user in the database"""
        try:
            if supabase:
                # Use Supabase
                result = supabase.table(self.table_name).insert(user_data).execute()
                return result.data[0] if result.data else None
            else:
                # Fallback to mock database
                user_data["id"] = str(uuid.uuid4())
                user_data["created_at"] = datetime.utcnow().isoformat()
                return user_data
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            # Fallback for demo
            user_data["id"] = str(uuid.uuid4())
            user_data["created_at"] = datetime.utcnow().isoformat()
            return user_data
    
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            if supabase:
                result = supabase.table(self.table_name).select("*").eq("email", email).execute()
                return result.data[0] if result.data else None
            else:
                return None
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            return None
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            if supabase:
                result = supabase.table(self.table_name).select("*").eq("id", user_id).execute()
                return result.data[0] if result.data else None
            else:
                return None
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            return None
    
    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update user data"""
        try:
            if supabase:
                result = supabase.table(self.table_name).update(update_data).eq("id", user_id).execute()
                return result.data[0] if result.data else None
            else:
                return None
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            return None
    
    async def update_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        await self.update_user(user_id, {"last_login": datetime.utcnow().isoformat()})

class RefreshTokenDatabase:
    def __init__(self):
        self.table_name = "refresh_tokens"
        
    async def create_refresh_token(self, user_id: str, token: str, expires_at: datetime) -> Dict[str, Any]:
        """Create a refresh token"""
        token_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "token": token,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True
        }
        
        try:
            if supabase:
                result = supabase.table(self.table_name).insert(token_data).execute()
                return result.data[0] if result.data else token_data
            else:
                # Fallback to mock
                MOCK_REFRESH_TOKENS[token] = token_data
                return token_data
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            MOCK_REFRESH_TOKENS[token] = token_data
            return token_data
    
    async def get_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get refresh token by token value"""
        try:
            if supabase:
                result = supabase.table(self.table_name).select("*").eq("token", token).eq("is_active", True).execute()
                return result.data[0] if result.data else None
            else:
                return MOCK_REFRESH_TOKENS.get(token)
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            return MOCK_REFRESH_TOKENS.get(token)
    
    async def invalidate_refresh_token(self, token: str) -> bool:
        """Invalidate a refresh token"""
        try:
            if supabase:
                result = supabase.table(self.table_name).update({"is_active": False}).eq("token", token).execute()
                return len(result.data) > 0
            else:
                if token in MOCK_REFRESH_TOKENS:
                    MOCK_REFRESH_TOKENS[token]["is_active"] = False
                    return True
                return False
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            if token in MOCK_REFRESH_TOKENS:
                MOCK_REFRESH_TOKENS[token]["is_active"] = False
                return True
            return False
    
    async def cleanup_expired_tokens(self):
        """Clean up expired refresh tokens"""
        try:
            if supabase:
                current_time = datetime.utcnow().isoformat()
                supabase.table(self.table_name).delete().lt("expires_at", current_time).execute()
            else:
                # Cleanup mock tokens
                current_time = datetime.utcnow()
                expired_tokens = [
                    token for token, data in MOCK_REFRESH_TOKENS.items()
                    if datetime.fromisoformat(data["expires_at"]) < current_time
                ]
                for token in expired_tokens:
                    del MOCK_REFRESH_TOKENS[token]
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")

class AuditLogDatabase:
    def __init__(self):
        self.table_name = "audit_logs"
        
    async def create_audit_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an audit log entry"""
        log_entry = {
            "id": str(uuid.uuid4()),
            "user_id": log_data["user_id"],
            "action": log_data["action"],
            "endpoint": log_data.get("endpoint"),
            "ip_address": log_data.get("ip_address"),
            "user_agent": log_data.get("user_agent"),
            "timestamp": datetime.utcnow().isoformat(),
            "details": log_data.get("details")
        }
        
        try:
            if supabase:
                result = supabase.table(self.table_name).insert(log_entry).execute()
                return result.data[0] if result.data else log_entry
            else:
                # Fallback to mock
                MOCK_AUDIT_LOGS.append(log_entry)
                return log_entry
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            MOCK_AUDIT_LOGS.append(log_entry)
            return log_entry
    
    async def get_audit_logs(self, user_id: Optional[str] = None, action: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs with optional filtering"""
        try:
            if supabase:
                query = supabase.table(self.table_name).select("*")
                if user_id:
                    query = query.eq("user_id", user_id)
                if action:
                    query = query.eq("action", action)
                result = query.order("timestamp", desc=True).limit(limit).execute()
                return result.data if result.data else []
            else:
                # Filter mock logs
                logs = MOCK_AUDIT_LOGS
                if user_id:
                    logs = [log for log in logs if log["user_id"] == user_id]
                if action:
                    logs = [log for log in logs if log["action"] == action]
                return sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:limit]
        except Exception as e:
            logger.error(f"Database error: {type(e).__name__}")
            return []

class TokenBlacklist:
    def __init__(self):
        self.blacklisted_tokens = set()
        
    def blacklist_token(self, token: str):
        """Add token to blacklist"""
        self.blacklisted_tokens.add(token)
    
    def is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        return token in self.blacklisted_tokens
    
    def cleanup_expired_tokens(self, expired_tokens: List[str]):
        """Remove expired tokens from blacklist"""
        for token in expired_tokens:
            self.blacklisted_tokens.discard(token)

# Global database instances
user_db = UserDatabase()
refresh_token_db = RefreshTokenDatabase()
audit_log_db = AuditLogDatabase()
token_blacklist = TokenBlacklist()

# Mock storage for demo (when database is not available)
MOCK_USERS = {}
MOCK_REFRESH_TOKENS = {}
MOCK_AUDIT_LOGS = []

async def get_user_by_email_mock(email: str) -> Optional[Dict[str, Any]]:
    """Mock function to get user by email"""
    return MOCK_USERS.get(email)

async def create_user_mock(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Mock function to create user"""
    user_data["id"] = str(uuid.uuid4())
    user_data["created_at"] = datetime.utcnow().isoformat()
    MOCK_USERS[user_data["email"]] = user_data
    return user_data

async def log_audit_event(user_id: str, action: str, endpoint: Optional[str] = None, 
                         ip_address: Optional[str] = None, user_agent: Optional[str] = None, 
                         details: Optional[Dict[str, Any]] = None):
    """Log an audit event"""
    log_data = {
        "user_id": user_id,
        "action": action,
        "endpoint": endpoint,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "details": details
    }
    return await audit_log_db.create_audit_log(log_data)
