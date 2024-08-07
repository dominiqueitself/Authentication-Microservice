from flask import Flask, jsonify, request
import json
import mysql.connector

app = Flask(__name__)

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
        return jsonify({"success": TRUE, "authorization": employee[2]})    
    else:
        return jsonify({"failed": FALSE})

@app.route('/authentication', methods=['POST'])
def authenticate():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    return get_employees(email, password)

#need pa itesting
#need pa ideploy
#need pa makuha yung input - backend sa login tapos isend sa dito yung email at password para macheck

if __name__ == '__main__':
    app.run(debug=True)
