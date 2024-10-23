from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import json
import jwt
import pytz
import datetime
import os

app = Flask(__name__)

# JWT configuration for password checking and token generation
header = {  
  "alg": "HS256",  
  "typ": "JWT",
}  

# Secret key (move this to an environment variable for better security)
secret_key = "&Hygf%mGko"

# Connect to the authentication database (PostgreSQL)
authdb = psycopg2.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    dbname=os.getenv("DB_NAME")
)

# authdb = psycopg2.connect(
#     host="localhost",
#     user="postgres",  # Change to ur PostgreSQL user
#     password="fms-group3",  # Change to ur PostgreSQL password
#     dbname="authentication"
# )
authdb.autocommit = True  # Enable autocommit for PostgreSQL
authcursor = authdb.cursor()

# Function for generating a JWT token
def generate_token(username, roleName):
    payload = {
        "username": username,
        "role": roleName,
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=60),  # Token expiration time
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")
    return token
    
# Function to check employee credentials
def check_employees(username, password):
    sql = """SELECT u.username, u.hashPassword, a.roleName, u.accountLocked 
             FROM USERS u
             JOIN AUTHORIZATIONS a ON u.authorizationId = a.authorizationId
             WHERE u.username = %s"""
    
    authcursor.execute(sql, (username,))
    employee = authcursor.fetchone()

    if employee:
        if employee[3]:  # Check if account is locked
            return jsonify({"error": 'Your account is locked. Please contact tech support.'}), 403
        
        # Unpack the retrieved fields
        username, hashPassword, roleName = employee[:3]
        if check_password_hash(hashPassword, password):
            token = generate_token(username, roleName)
            return jsonify({"token": token}), 200
        else:
            return jsonify({"error": 'Invalid credentials'}), 401
    else:
        return jsonify({"error": 'Invalid credentials'}), 401

# API route to authenticate and generate a token
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    response = check_employees(username, password)
    
    if response is None:
        return jsonify({"error": "Unexpected error occurred."}), 500
    
    return response

# API route to verify a token
@app.route('/verify-token', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get('token')

    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        return jsonify({
            "username": decoded_token["username"],
            "role": decoded_token["role"]
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

# Function to insert a new user into the USERS table
def create_user(username, password, email, contactNumber, authorizationId):
    hashed_password = generate_password_hash(password)
    sql = """INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId, accountLocked) 
             VALUES (%s, %s, %s, %s, %s, %s)"""
    values = (username, hashed_password, email, contactNumber, authorizationId, False)
    
    authcursor.execute(sql, values)

# This part will run automatically to insert users
@app.route('/')
def generate_users():
    try:
        create_user("finmanager", "fin123", "finmanager@company.com", "09210000004", 1)
        create_user("billingspec", "billing123", "billingspec@company.com", "09210000005", 2)
        create_user("sysadmin", "admin123", "sysadmin@company.com", "09210000006", 3)
        create_user("claimsspec", "claims123", "claimsspec@company.com", "09210000007", 4)

        # Added users for PMS & LMS
        create_user("pms_user", "pms123", "pmsuser@company.com", "09210000008", 8)  # Patient Management System user
        create_user("lms_user", "lms123", "lmsuser@company.com", "09210000009", 9)  # Logistics Management System user

        return jsonify({"message": "Users created successfully"}), 201
    except psycopg2.Error as err:
        return jsonify({"error": str(err)}), 400

# API route to lock an account
@app.route('/accountLocked', methods=['POST'])
def accountLocked():
    data = request.get_json()
    username = data.get('username')
    authcursor.execute("UPDATE USERS SET accountLocked = TRUE WHERE username = %s", (username,))
    return jsonify({"message": "Account locked"}), 200

if __name__ == '__main__':
    app.run(port=3307, debug=True)
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import json
import jwt
import pytz
import datetime

app = Flask(__name__)

# JWT configuration for password checking and token generation
header = {  
  "alg": "HS256",  
  "typ": "JWT",
}  

# Secret key (move this to an environment variable for better security)
secret_key = "&Hygf%mGko"

# Connect to the authentication database (PostgreSQL)
authdb = psycopg2.connect(
    host="localhost",
    user="postgres",  # Your PostgreSQL user
    password="fms-group3",  # Your PostgreSQL password
    dbname="authentication"
)
authdb.autocommit = True  # Enable autocommit for PostgreSQL
authcursor = authdb.cursor()

# Function for generating a JWT token
def generate_token(username, roleName):
    payload = {
        "username": username,
        "role": roleName,
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=60),  # Token expiration time
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")
    return token
    
# Function to check employee credentials
def check_employees(username, password):
    sql = """SELECT u.username, u.hashPassword, a.roleName, u.accountLocked 
             FROM USERS u
             JOIN AUTHORIZATIONS a ON u.authorizationId = a.authorizationId
             WHERE u.username = %s"""
    
    authcursor.execute(sql, (username,))
    employee = authcursor.fetchone()

    if employee:
        if employee[3]:  # Check if account is locked
            return jsonify({"error": 'Your account is locked. Please contact tech support.'}), 403
        
        # Unpack the retrieved fields
        username, hashPassword, roleName = employee[:3]
        if check_password_hash(hashPassword, password):
            token = generate_token(username, roleName)
            return jsonify({"token": token}), 200
        else:
            return jsonify({"error": 'Invalid credentials'}), 401
    else:
        return jsonify({"error": 'Invalid credentials'}), 401

# API route to authenticate and generate a token
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    response = check_employees(username, password)
    
    if response is None:
        return jsonify({"error": "Unexpected error occurred."}), 500
    
    return response

# API route to verify a token
@app.route('/verify-token', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get('token')

    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        return jsonify({
            "username": decoded_token["username"],
            "role": decoded_token["role"]
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

# Function to insert a new user into the USERS table
def create_user(username, password, email, contactNumber, authorizationId):
    hashed_password = generate_password_hash(password)
    sql = """INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId, accountLocked) 
             VALUES (%s, %s, %s, %s, %s, %s)"""
    values = (username, hashed_password, email, contactNumber, authorizationId, False)
    
    authcursor.execute(sql, values)

# This part will run automatically to insert users
@app.route('/')
def generate_users():
    try:
        create_user("finmanager", "fin123", "finmanager@company.com", "09210000004", 1)
        create_user("billingspec", "billing123", "billingspec@company.com", "09210000005", 2)
        create_user("sysadmin", "admin123", "sysadmin@company.com", "09210000006", 3)
        create_user("claimsspec", "claims123", "claimsspec@company.com", "09210000007", 4)
        return jsonify({"message": "Users created successfully"}), 201
    except psycopg2.Error as err:
        return jsonify({"error": str(err)}), 400

# API route to lock an account
@app.route('/accountLocked', methods=['POST'])
def accountLocked():
    data = request.get_json()
    username = data.get('username')
    authcursor.execute("UPDATE USERS SET accountLocked = TRUE WHERE username = %s", (username,))
    return jsonify({"message": "Account locked"}), 200

if __name__ == '__main__':
    app.run(port=3307, debug=True)
