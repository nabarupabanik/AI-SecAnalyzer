
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
