from flask import Flask, jsonify, request
import json
import mysql.connector
import jwt

app = Flask(__name__)

header = {  
  "alg": "HS256",  
  "typ": "JWT"  
}  
key = "&Hygf%mGko"

authdb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "root",
    database = "authenticationMicroservice"
)

authcursor = authdb.cursor()

def get_employees(email, password):

    query = "SELECT email, password, authorization FROM employees WHERE email = %s AND password = %s"
    authcursor.execute(query, (email, password))
    employee = authcursor.fetchone()
    authdb.close()
    
    if employee: 
        token = jwt.encode({'email': email}, {'authorization': authorization}, key, algorithm='HS256')
        return jsonify({"token": token})    
    else:
        return jsonify({"message": 'Invalid credentials'})

@app.route('/authentication', methods=['POST'])
def authenticate():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    return get_employees(email, password)

if __name__ == '__main__':
    app.run(debug=True)
