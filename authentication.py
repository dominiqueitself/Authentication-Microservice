from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector as mysql
import json
import jwt
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
    password = "buchibi",
    database = "authentication"
)
authcursor = authdb.cursor()

#function - for generating a token
def generate_token(username, authorizationId):
    payload = {
        "username": username,
        "authorization ID": authorizationId,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        "Content-Type": "application/json",
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")
    return token

#function - for checking the user's username and password
def check_employees(username, password):
    authcursor.execute("SELECT username, hashPassword, authorizationId FROM USERS WHERE username = %s", (username,) )
    employee = authcursor.fetchone()

    if employee and check_password_hash(employee[1], password): 
        username, hashPassword, authorizationId = employee
        token = generate_token(username, authorizationId)
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
