"""
Test file with actual vulnerabilities to demonstrate exploit chain detection
"""

def login(username, password):
    # SQL Injection vulnerability - Entry point
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = execute_query(query)
    user = cursor.fetchone()
    
    if user:
        # Store user data in session
        session['user_id'] = user['id']
        session['is_admin'] = user.get('is_admin', False)
        return True
    return False

def execute_query(query):
    """Database query execution"""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor

def get_user_profile(user_id):
    # Another SQL injection - Privilege escalation potential
    query = f"SELECT * FROM user_profiles WHERE user_id = {user_id}"
    return execute_query(query)

def admin_dashboard():
    # Check admin privileges
    if session.get('is_admin'):
        return "Admin access granted"
    return "Access denied"

def update_user_settings(user_id, setting, value):
    # XSS vulnerability - Data sink
    user_profile = get_user_profile(user_id)
    message = f"Updated {setting} to {value} for user {user_profile['name']}"
    return message

def process_file_upload(filename):
    # Path traversal vulnerability
    filepath = f"/uploads/{filename}"
    with open(filepath, 'r') as f:
        content = f.read()
    return content
