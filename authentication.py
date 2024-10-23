from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import json
import jwt
import pytz
import datetime
import os
from dotenv import load_dotenv  # Import to load .env

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# JWT configuration for password checking and token generation
header = {  
    "alg": "HS256",  
    "typ": "JWT",
}  

# Secret key for JWT
secret_key = os.getenv('SECRET_KEY', "&Hygf%mGko")

# Connect to the authentication database (PostgreSQL)
try:
    authdb = psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'fms-group3'),
        dbname=os.getenv('DB_NAME', 'authentication')
    )
    authdb.autocommit = True  # Enable autocommit for PostgreSQL
    authcursor = authdb.cursor()
    print(f"Successfully connected to the database at {os.getenv('DB_HOST')}")
except psycopg2.Error as e:
    print(f"Error connecting to the database: {e}")

# Function to print all tables in the database
def print_tables():
    try:
        authcursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
        tables = authcursor.fetchall()
        print("Tables in the database:")
        for table in tables:
            print(table[0])
    except psycopg2.Error as e:
        print(f"Error fetching tables: {e}")

print_tables()  # Call the function to print tables

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
             FROM users u  -- Adjusted to lowercase
             JOIN authorizations a ON u.authorizationId = a.authorizationId
             WHERE u.username = %s"""
    
    try:
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
    except psycopg2.Error as e:
        print(f"Error executing query: {e}")
        return jsonify({"error": "Database error occurred."}), 500

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
    sql = """INSERT INTO users (username, hashPassword, email, contactNumber, authorizationId, accountLocked) 
             VALUES (%s, %s, %s, %s, %s, %s)"""  # Adjusted to lowercase
    values = (username, hashed_password, email, contactNumber, authorizationId, False)
    
    try:
        authcursor.execute(sql, values)
    except psycopg2.IntegrityError:
        authdb.rollback()  # Rollback in case of unique constraint violation
        print(f"User {username} already exists. Skipping.")

# This part will run automatically to insert users
@app.route('/generate-users', methods=['POST'])
def generate_users():
    try:
        users = [
            ("finmanager", "fin123", "finmanager@company.com", "09210000004", 1),
            ("billingspec", "billing123", "billingspec@company.com", "09210000005", 2),
            ("sysadmin", "admin123", "sysadmin@company.com", "09210000006", 3),
            ("claimsspec", "claims123", "claimsspec@company.com", "09210000007", 4),
            ("pms_user", "pms123", "pmsuser@company.com", "09210000008", 8),
            ("lms_user", "lms123", "lmsuser@company.com", "09210000009", 9)
        ]

        for username, password, email, contactNumber, authorizationId in users:
            create_user(username, password, email, contactNumber, authorizationId)

        return jsonify({"message": "Users created successfully"}), 201
    except psycopg2.Error as err:
        return jsonify({"error": str(err)}), 400

# API route to lock an account
@app.route('/accountLocked', methods=['POST'])
def accountLocked():
    data = request.get_json()
    username = data.get('username')
    # Check if user exists before attempting to lock
    authcursor.execute("SELECT username FROM users WHERE username = %s", (username,))  # Adjusted to lowercase
    if not authcursor.fetchone():
        return jsonify({"error": "User not found."}), 404
    
    authcursor.execute("UPDATE users SET accountLocked = TRUE WHERE username = %s", (username,))  # Adjusted to lowercase
    return jsonify({"message": "Account locked"}), 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000, debug=True)
