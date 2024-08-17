from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector as mysql
import json
import jwt
import pytz
import datetime 

app = Flask(__name__)

#for generating and checking password
header = {  
  "alg": "HS256",  
  "typ": "JWT",
}  

#secret key - kailangan pang iseperate sa .env file
secret_key = "&Hygf%mGko" 

#connecting to the database
authdb = mysql.connect(
    host = "localhost",
    user = "root",
    password = "fms-group3",
    database = "authentication"
)
authcursor = authdb.cursor()

#function - for generating a token
def generate_token(username, roleName):
    payload = {
        "username": username,
        "role": roleName,  # Use role name here
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=30),
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")
    return token

#function - for checking the user's username and password
def check_employees(username, password):
    authcursor.execute("SELECT username, hashPassword, authorizationId FROM USERS WHERE username = %s", (username,) )
    employee = authcursor.fetchone()

    if employee and check_password_hash(employee[1], password): 
        username, authorizationId = employee
        token = generate_token(username, authorizationId)
        return jsonify({"token": token}), 200
    elif employee:
        return jsonify({"error": 'Invalid credentials'}), 401
    else:
        return jsonify({"error": 'Unexpected Error'})

@app.route('/verify-token', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get('token')

    try:
        # Decode the token
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])

        # Return the username and role name instead of ID
        return jsonify({
            "username": decoded_token["username"],
            "role": decoded_token["role"] 
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    
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
    elif employee is None:
        return jsonify({"error": 'Invalid credentials'}), 401

#API route for checking the user's credential and sending out result
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    return check_employees(username, password)

@app.route('/accountLocked', methods=['POST'])
def accountLocked():
    data = request.get_json()
    username = data.get('username')
    authcursor.execute("UPDATE USERS SET accountLocked = TRUE WHERE username = %s", (username,))
    return True

""" just for adding users in the database
@app.route('/')
def generate_password():
    password = generate_password_hash("maingayKAYO")
    values = ("dominique", password, "shanejain00@gmail.com", '09213373131', 2)

    sql = "INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId) VALUES (%s, %s, %s, %s, %s)"
    authcursor.execute(sql, values)
    authdb.commit()
    authcursor.close()
    authdb.close()
    return 200
"""
if __name__ == '__main__':
    app.run(port=3307, debug=True)
