
import os
import subprocess

# SQL Injection vulnerability
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# Hardcoded password vulnerability
def connect_db():
    password = "admin123"
    return connect(password)

# Command injection vulnerability  
def list_files(user_input):
    os.system(f"ls {user_input}")
    return result
