from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os

app = Flask(__name__)

# Hardcoded secrets — Trivy secret scanner will catch these
AWS_ACCESS_KEY    = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN      = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
DB_PASSWORD       = "admin123"
JWT_SECRET        = "my_jwt_secret_never_share_this"
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

@app.route('/')
def home():
    return {"status": "running", "app": "trivy-poc"}

# SQL Injection vulnerability
@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect(':memory:')
    query = "SELECT * FROM users WHERE id = " + user_id  # BAD
    try:
        conn.execute(query)
    except:
        pass
    return {"query": query}

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    result = subprocess.run(
        f"ping -c 1 {host}",  # BAD: user input in shell command
        shell=True,
        capture_output=True
    )
    return {"output": result.stdout.decode()}

# Weak hashing
@app.route('/hash')
def make_hash():
    password = request.args.get('password', 'test')
    hashed = hashlib.md5(password.encode()).hexdigest()  # BAD: MD5
    return {"hash": hashed}

if __name__ == '__main__':
    # BAD: debug=True, exposed to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000)
