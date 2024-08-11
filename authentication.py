from flask import Flask, jsonify, request
import json
import mysql.connector as mysql
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime 

app = Flask(__name__)

#for generating and checking password
header = {  
  "alg": "HS256",  
  "typ": "JWT",
  "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
  "Content-Type": "application/json",
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
    }
    token = jwt.encode(payload=payload, header=header)
    return token

#function - for checking the user's username and password
def check_employees(username, password):

    authcursor.execute("SELECT username, authorizationId FROM USERS WHERE email = %s", (username,) )
    employee = authcursor.fetchone()

    if username and check_password_hash(employee[1], password): 
        username, authorizationId = employee
        token = generate_token(username, authorizationId)
        return jsonify({"token": token}), 200
    elif username == 0:
        return jsonify({"error": 'Invalid credentials'}), 401

#API route for checking the user's credential and sending out result
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    #calling the check_employee function
    result = check_employees(username, password)

    #returns the result of the checking of the user's credentials
    return jsonify(result) 

if __name__ == '__main__':
    app.run(port=3307, debug=True)
