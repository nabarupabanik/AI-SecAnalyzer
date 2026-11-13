#!/usr/bin/env python3
"""
Create test files with vulnerabilities to test AI suggestions in frontend
"""

import os

def create_test_files():
    """Create test files with vulnerabilities that will trigger AI suggestions"""
    
    # Create test directory
    test_dir = "test_ai_vulnerabilities"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    # Create Python file with SQL injection
    sql_injection_code = '''
import sqlite3

def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SQL Injection vulnerability
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_name(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Another SQL injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    
    user = cursor.fetchone()
    conn.close()
    return user
'''
    
    with open(os.path.join(test_dir, "sql_injection.py"), "w") as f:
        f.write(sql_injection_code)
    
    # Create Python file with hardcoded secrets
    secrets_code = '''
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
'''
    
    with open(os.path.join(test_dir, "hardcoded_secrets.py"), "w") as f:
        f.write(secrets_code)
    
    # Create Python file with command injection
    command_injection_code = '''
import os
import subprocess

def list_files(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    return True

def process_data(data):
    # Another command injection
    os.system(f"cat {data}")
    return True

def run_command(cmd):
    # Using shell=True is dangerous
    subprocess.run(cmd, shell=True)
    return True
'''
    
    with open(os.path.join(test_dir, "command_injection.py"), "w") as f:
        f.write(command_injection_code)
    
    print(f"Created test files in '{test_dir}' directory:")
    print(f"  - sql_injection.py (SQL injection vulnerabilities)")
    print(f"  - hardcoded_secrets.py (Hardcoded secret vulnerabilities)")
    print(f"  - command_injection.py (Command injection vulnerabilities)")
    print()
    print("Now run a scan on this directory to see AI suggestions in the frontend!")
    print(f"Scan command: python -m scanner.main {test_dir}")

if __name__ == "__main__":
    create_test_files()
