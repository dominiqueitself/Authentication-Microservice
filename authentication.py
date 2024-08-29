from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector as mysql
import json
import jwt
import pytz
import datetime
import os
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")

#connecting to the database
authdb = mysql.connect(
    host = os.getenv("DB_HOST"),
    user = os.getenv("DB_USER"),
    password = os.getenv("DB_PASSWORD"),
    database = os.getenv("DB_NAME")
)
authcursor = authdb.cursor()

# FUNCTIONS

# generating a token
def generate_token(username, role_name):
    payload = {
        "username": username,
        "role": role_name,
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=30),
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=app.secret_key, algorithm="HS256")
    return token

# checking the user's username and password
def check_employees(username, password):
    sql = """SELECT u.username, u.hashed_password, a.role_name
             FROM USERS u
             JOIN AUTHORIZATIONS a ON u.authorization_id = a.authorization_id
             WHERE u.username = %s"""

    authcursor.execute(sql, (username,))
    employee = authcursor.fetchone()

    if employee and check_password_hash(employee[1], password):
        username, hashed_password, role_name = employee
        token = generate_token(username, role_name)
        return jsonify({"token": token}), 200
    elif employee:
        return jsonify({"error": 'Invalid credentials'}), 401
    else:
        return jsonify({"error": 'Unexpected Error'})


# API ROUTES

@app.route('/')
def home():
    return "Welcome to the Authentication Microservices API"

# for verifying the token of the user to access certain modules
@app.route('/verify-token', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get('token')

    try:
        # Decode the token
        decoded_token = jwt.decode(token, app.secret_key, algorithms=["HS256"])

        # Return the username and role name instead of ID
        return jsonify({
            "username": decoded_token["username"],
            "role": decoded_token["role"]
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# checking the user's credential
@app.route('/account/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    return check_employees(username, password)

# for locking the users account when login attempts have exceeded
@app.route('/account/locked', methods=['POST'])
def account_locked():
    data = request.get_json()
    username = data.get('username')
    authcursor.execute("UPDATE USERS SET accountLocked = TRUE WHERE username = %s", (username,))
    return True

@app.route('/account/check', methods=['POST'])
def check_account():
    email = request.json.get('email')
    authcursor.execute("SELECT email FROM USERS WHERE email = %s", (email,))
    if authcursor.fetchone():
        return jsonify({"result": True}), 200
    else:
        return jsonify({"result": False}), 404

if __name__ == '__main__':
    app.run(port=3307, debug=True)
