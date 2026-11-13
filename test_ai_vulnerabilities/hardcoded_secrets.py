
import os

# Hardcoded password vulnerability
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def connect_to_database():
    password = "secret_password"
    return password

def get_api_config():
    # More hardcoded secrets
    config = {
        "password": "hardcoded_pass",
        "token": "secret_token_123"
    }
    return config
