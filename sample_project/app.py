"""
sample_project/app.py
Main entry point for the sample Flask web app.
(Intentionally contains vulnerabilities for Sprint 2+ testing)
"""
import os
import subprocess
from flask import Flask, request, render_template

app = Flask(__name__)

# Hardcoded secret — BAD PRACTICE (for testing Scanner Sprint 2)
SECRET_KEY = "hardcoded_secret_abc123"
DB_PASSWORD = "admin123"

DEBUG = True  # Should never be True in production


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # SQL Injection vulnerability (for Sprint 2 detection)
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    return f"Running: {sql}"


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd", "")
    # Command injection vulnerability (for Sprint 2 detection)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
