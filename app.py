from flask import Flask, request, jsonify
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
import sqlite3
import base64
import json

app = Flask(__name__)

# SQLite Database Initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        user_name TEXT NOT NULL,
                        credential_data BLOB NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# Register options: Generate registration options and send to frontend
@app.route('/register_options', methods=['POST'])
def register_options():
    user_id = request.json.get("user_id")
    user_name = request.json.get("user_name")

    registration_options = generate_registration_options(
        rp_name="StreamlitApp",
        rp_id="localhost",
        user_id=user_id,
        user_name=user_name,
        user_display_name=user_name
    )

    # Store registration options temporarily for verification later
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO users (user_id, user_name, credential_data) VALUES (?, ?, ?)",
                   (user_id, user_name, json.dumps(registration_options)))
    conn.commit()
    conn.close()

    return jsonify(registration_options)

# Register response: Verify registration data (attestation)
@app.route('/register_response', methods=['POST'])
def register_response():
    user_id = request.json.get("user_id")
    response_data = request.json.get("response_data")

    # Retrieve stored registration options
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT credential_data FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "User not found!"}), 400

    registration_options = json.loads(row[0])

    try:
        credential = verify_registration_response(
            credential=response_data,
            expected_rp_id="localhost",
            expected_origin="http://localhost:8501"
        )
        
        # Store the user's public key credential
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET credential_data = ? WHERE user_id = ?",
                       (json.dumps(credential), user_id))
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": "Registration successful!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# Login options: Generate authentication options for login
@app.route('/login_options', methods=['POST'])
def login_options():
    user_id = request.json.get("user_id")

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT credential_data FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "User not found!"}), 400

    credential_data = json.loads(row[0])
    authentication_options = generate_authentication_options(
        rp_id="localhost",
        user_id=user_id,
        allow_credentials=[credential_data]
    )

    return jsonify(authentication_options)

# Login response: Verify the login attempt (assertion)
@app.route('/login_response', methods=['POST'])
def login_response():
    user_id = request.json.get("user_id")
    response_data = request.json.get("response_data")

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT credential_data FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "User not found!"}), 400

    credential_data = json.loads(row[0])

    try:
        result = verify_authentication_response(
            credential=response_data,
            expected_rp_id="localhost",
            expected_origin="http://localhost:8501",
            allow_credentials=[credential_data]
        )
        return jsonify({"status": "success", "message": "Authentication successful!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
