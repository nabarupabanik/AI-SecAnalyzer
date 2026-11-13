"""
sample_project/login.py
Handles user authentication.
"""
import hashlib


def authenticate(username: str, password: str) -> bool:
    """Authenticate a user against the database."""
    # Weak hashing — MD5 (for Sprint 2 detection)
    hashed = hashlib.md5(password.encode()).hexdigest()
    # In a real app, query the database here
    stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
    return hashed == stored_hash


def create_session(user_id: int) -> str:
    """Create a weak session token."""
    import random
    # Insecure random — predictable (for Sprint 2 detection)
    token = str(random.randint(100000, 999999))
    return token


if __name__ == "__main__":
    result = authenticate("admin", "password")
    print(f"Auth result: {result}")
