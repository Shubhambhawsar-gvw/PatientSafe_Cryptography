from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import bcrypt
import json
import os

app = Flask(__name__)

# Generate or load the secret key 1
KEY_FILE = "secret.key"

def generate_key():
    """Generate and save a secret key (Run once)"""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        print("🔑 Secret key generated and saved.")

def load_key():
    """Load the existing secret key"""
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()
    
# Function to hash a password
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

# Function to check a password against a hash
def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Ensure key exists before running the API
generate_key()
fernet = Fernet(load_key())

@app.route("/encrypt", methods=["POST"])
def encrypt_json():
    """Encrypts the input JSON and returns encrypted data"""
    try:
        data = request.get_json()
        json_string = json.dumps(data)
        encrypted_message = fernet.encrypt(json_string.encode())
        return jsonify({"encrypted_data": encrypted_message.decode()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_json():
    """Decrypts the encrypted data and returns original JSON"""
    try:
        data = request.get_json()
        print (data)
        encrypted_data = data.get("text")
        #encrypted_data = request.json.get("encrypted_data")
        decrypted_message = fernet.decrypt(encrypted_data.encode()).decode()
        return jsonify(json.loads(decrypted_message)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Route to hash a password
# Route to hash a password
@app.route('/hash', methods=['POST'])
def hash_route():
    data = request.get_json()
    print(data)
    
    # Accept password from either 'password' or 'text' key
    password = data.get('password') or data.get('text')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    hashed = hash_password(password)
    return jsonify({"hashed_password": hashed})


# Route to verify a password
@app.route('/verify', methods=['POST'])
def verify_route():
    data = request.get_json()
    print(data)

    # Accept password from 'password' or 'text'
    password = data.get('password') or data.get('text')
    hashed_password = data.get('hashed_password')

    if not password or not hashed_password:
        return jsonify({"error": "Both password and hashed_password are required"}), 400

    is_valid = check_password(password, hashed_password)
    return jsonify({"password_match": is_valid})


if __name__ == "__main__":
    app.run(debug=False, port = 6666)
