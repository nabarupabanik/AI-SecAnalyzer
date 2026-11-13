
from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

@app.route('/user/<int:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL Injection vulnerability
    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
    user = cursor.fetchone()
    conn.close()
    
    return render_template('user.html', user=user)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Hardcoded secret vulnerability
    admin_password = 'admin123'
    
    if username == 'admin' and password == admin_password:
        return 'Login successful'
    
    return 'Login failed'

@app.route('/profile')
def profile():
    user_input = request.args.get('data', '')
    
    # XSS vulnerability
    return render_template('profile.html', data=user_input)

if __name__ == '__main__':
    app.run(debug=True)
