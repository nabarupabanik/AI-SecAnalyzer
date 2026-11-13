
def execute_query(query):
    import sqlite3
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL Injection vulnerability
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    
    return result

def process_user_data(data):
    # XSS vulnerability
    return f"<div>User data: {data}</div>"
