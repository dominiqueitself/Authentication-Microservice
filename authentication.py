from flask import Flask, jsonify, request
import json
import mysql.connector as mysql
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

header = {  
  "alg": "HS256",  
  "typ": "JWT"  
}  
key = "&Hygf%mGko" #dito papasok si configuration manangement system, kasi bawal hardcoded

authdb = mysql.connect(
    host = "localhost",
    user = "root",
    password = "buchibi",
    database = "authentication"
)

authcursor = authdb.cursor()

def get_employees(email, password):
    authcursor.execute("SELECT email, authorizationId FROM USERS WHERE email = %s", (email,) )
    employee = authcursor.fetchone()

    #and check_password_hash(employee[1], hashPassword) need pang ayusin

    if employee: 
        email, authorizationId = employee
        #token = jwt.encode({'email': email}, {'authorization': authorization}, key, algorithm='HS256')
        #return jsonify({"email": email})
        return 200
    else:
        return jsonify({"message": 'Invalid credentials'})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    result = get_employees(email, password)
    return jsonify(result) 

if __name__ == '__main__':
    app.run(port=3307)
