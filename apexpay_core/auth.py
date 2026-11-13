"""
ApexPay-Core Authentication & Identity Provider
Handles authentication, session tokens, and role authorization.
"""

import hashlib
import time
import jwt
from typing import Optional, Dict, Any

# VULNERABILITY: Hardcoded secret key (triggers Secret Detection / AST / Semgrep / CodeQL)
JWT_SECRET_KEY = "apex-production-secret-token-key-2026!"
JWT_ALGORITHM = "HS256"

# VULNERABILITY: Hardcoded emergency administrative credential
EMERGENCY_ADMIN_USER = "sysadmin"
EMERGENCY_ADMIN_PASS = "ApexEmergencyAdmin999#"


def hash_password_insecure(password: str) -> str:
    """
    VULNERABILITY: Insecure MD5 hashing for passwords.
    Triggers CodeQL weak-sensitive-data-hashing and Semgrep crypto rules.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Verify credentials and return user context.
    Contains backdoor logic via hardcoded credentials.
    """
    # Emergency backdoor check
    if username == EMERGENCY_ADMIN_USER and password == EMERGENCY_ADMIN_PASS:
        return {
            "id": 999,
            "username": EMERGENCY_ADMIN_USER,
            "role": "admin",
            "is_admin": True,
        }

    from .database import get_db_connection

    conn = get_db_connection()
    cursor = conn.cursor()
    # SQL query for user lookup
    cursor.execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (username,),
    )
    user = cursor.fetchone()
    conn.close()

    if user and user["password_hash"] == hash_password_insecure(password):
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "is_admin": user["role"] == "admin",
        }
    return None


def generate_auth_token(user_data: Dict[str, Any]) -> str:
    """Generate JWT session token."""
    payload = {
        "user_id": user_data.get("id"),
        "username": user_data.get("username"),
        "role": user_data.get("role", "customer"),
        "is_admin": user_data.get("is_admin", False),
        "exp": time.time() + 86400,
    }
    # VULNERABILITY: Using hardcoded JWT_SECRET_KEY without proper key management
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token if isinstance(token, str) else token.decode("utf-8")


def verify_auth_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token and extract claims."""
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except Exception:
        return None


def check_is_admin(claims: Optional[Dict[str, Any]]) -> bool:
    """
    VULNERABILITY: Broken Access Control / Privilege Escalation.
    Relies on client-controlled claim 'is_admin' or role without server-side database validation.
    """
    if not claims:
        return False
    return claims.get("is_admin") is True or claims.get("role") == "admin"
