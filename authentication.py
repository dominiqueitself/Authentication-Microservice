from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector as mysql
import json
import jwt
import pytz
import datetime 
import os

app = Flask(__name__)

#for generating and checking password
header = {  
  "alg": "HS256",  
  "typ": "JWT",
}  

#secret key - kailangan pang iseperate sa .env file
app.secret_key = os.urandom(24)

#connecting to the database
authdb = mysql.connect(
    host = "localhost",
    user = "root",
    password = "buchibi",
    database = "authentication"
)
authcursor = authdb.cursor()

# FUNCTIONS

#function - for generating a token
def generate_token(username, roleName):
    payload = {
        "username": username,
        "role": roleName,
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=30),
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=app.secret_key, algorithm="HS256")
    return token

#function - for checking the user's username and password
def check_employees(username, password):
    sql = """SELECT u.username, u.hashPassword, a.roleName 
             FROM USERS u
             JOIN AUTHORIZATIONS a ON u.authorizationId = a.authorizationId
             WHERE u.username = %s"""
    
    authcursor.execute(sql, (username,))
    employee = authcursor.fetchone()

    if employee and check_password_hash(employee[1], password): 
        username, hashPassword, roleName = employee
        token = generate_token(username, roleName)
        return jsonify({"token": token}), 200
    elif employee:
        return jsonify({"error": 'Invalid credentials'}), 401
    else:
        return jsonify({"error": 'Unexpected Error'})


# API ROUTES

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


# for checking the user's credential and sending out result
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
"""
@app.route('/')
def generate_password():
    password = generate_password_hash("maingayKAYO")
    values = ("Dominique", password, "shanejain00@gmail.com", '09214473133', 1)

    sql = "INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId) VALUES (%s, %s, %s, %s, %s)"
    authcursor.execute(sql, values)
    authdb.commit()
    authcursor.close()
    authdb.close()
    return 200
"""

if __name__ == '__main__':
    app.run(port=3307, debug=True)
