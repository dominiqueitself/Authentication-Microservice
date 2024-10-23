from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector as mysql
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

# Secret key (this should be moved to an environment variable for security)
secret_key = "&Hygf%mGko" 

# Connect to the authentication database
authdb = mysql.connect(
    host = "localhost",
    user = "root",
    password = "fms-group3",
    database = "authentication"
)
authcursor = authdb.cursor()

# Function for generating a JWT token
def generate_token(username, roleName):
    payload = {
        "username": username,
        "role": roleName,
        "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=60),  # Increased expiration time
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

    print("Fetched employee data:", employee)  # Debugging line

    if employee:
        if employee[3]:  # Check if account is locked
            return jsonify({"error": 'Your account is locked. Please contact tech support.'}), 403
        
        # Unpack only the expected fields
        username, hashPassword, roleName = employee[:3]  # Adjust as necessary
        if check_password_hash(hashPassword, password):
            token = generate_token(username, roleName)
            return jsonify({"token": token}), 200
        else:
            print("Password check failed")  # Debugging line
            return jsonify({"error": 'Invalid credentials'}), 401
    else:
        print("No employee found")  # Debugging line
        return jsonify({"error": 'Invalid credentials'}), 401  # Return this if no employee found
    
# API route to authenticate and generate a token
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    response = check_employees(username, password)
    
    if response is None:
        return jsonify({"error": "Unexpected error occurred."}), 500  # Handle unexpected cases
    
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
    hashed_password = generate_password_hash(password)  # Hash the password
    sql = """INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId, accountLocked) 
             VALUES (%s, %s, %s, %s, %s, %s)"""
    values = (username, hashed_password, email, contactNumber, authorizationId, False)  # Set accountLocked to False
    
    authcursor.execute(sql, values)
    authdb.commit()

# This part will run automatically to insert users
# Temporarily add new users with hardcoded roles
@app.route('/')
def generate_users():
    try:
        create_user("finmanager", "fin123", "finmanager@company.com", "09210000004", 1)  # Finance Manager
        create_user("billingspec", "billing123", "billingspec@company.com", "09210000005", 2)  # Billing Specialist
        create_user("sysadmin", "admin123", "sysadmin@company.com", "09210000006", 3)  # System Admin
        create_user("claimsspec", "claims123", "claimsspec@company.com", "09210000007", 4)  # Claims Specialist
        return jsonify({"message": "Users created successfully"}), 201
    except mysql.Error as err:
        return jsonify({"error": str(err)}), 400

# API route to lock an account
@app.route('/accountLocked', methods=['POST'])
def accountLocked():
    data = request.get_json()
    username = data.get('username')
    authcursor.execute("UPDATE USERS SET accountLocked = TRUE WHERE username = %s", (username,))
    authdb.commit()
    return jsonify({"message": "Account locked"}), 200

if __name__ == '__main__':
    app.run(port=3307, debug=True)
