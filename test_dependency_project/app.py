#!/usr/bin/env python3
"""
Simple Flask application for testing dependency scanning
"""

from flask import Flask, request, jsonify
import requests
import urllib3

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello World!"

@app.route('/api/data')
def get_data():
    try:
        # Make a request to external API
        response = requests.get('https://api.example.com/data')
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
