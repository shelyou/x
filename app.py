from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token
import bcrypt
from datetime import timedelta

app = Flask(__name__)

# Setup JWT configuration
app.config['JWT_SECRET_KEY'] = 'secret-key-here'  # Ganti dengan kunci yang lebih kuat
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Dummy data for users (gunakan database nyata di produksi)
users = {}

# Register route (untuk demonstrasi)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed_password

    return jsonify({"message": "User registered successfully!"}), 201

# Login route untuk autentikasi
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users:
        return jsonify({"message": "User not found"}), 404

    stored_password = users[username]
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({"success": True, "token": access_token})

# Default route untuk menampilkan halaman login
@app.route('/')
def index():
    return render_template('index.html')  # Ini akan melayani file HTML

if __name__ == '__main__':
    app.run(debug=True)
