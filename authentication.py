from flask import Flask, jsonify, request
import json

app = Flask(__name__)

employees = [ 
    { 'id': 1, 'name': 'Ashley' }, 
    { 'id': 2, 'name': 'Kate' }, 
    { 'id': 3, 'name': 'Joe' }
    ]

@app.route('/employees', methods=['GET'])
def get_employees():
    return jsonify(employees)

if __name__ == '__main__':
    app.run(debug=True)
