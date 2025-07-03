import os
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from supabase import create_client, Client
import json

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
            print(f"Database error: {e}")
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
            print(f"Database error: {e}")
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
            print(f"Database error: {e}")
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
            print(f"Database error: {e}")
            return None
    
    async def update_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        await self.update_user(user_id, {"last_login": datetime.utcnow().isoformat()})

# Global database instance
user_db = UserDatabase()

# Mock users for demo (when database is not available)
MOCK_USERS = {}

async def get_user_by_email_mock(email: str) -> Optional[Dict[str, Any]]:
    """Mock function to get user by email"""
    return MOCK_USERS.get(email)

async def create_user_mock(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Mock function to create user"""
    user_data["id"] = str(uuid.uuid4())
    user_data["created_at"] = datetime.utcnow().isoformat()
    MOCK_USERS[user_data["email"]] = user_data
    return user_data
