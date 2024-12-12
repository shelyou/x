from flask import Flask, request, jsonify, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import re
import logging
from datetime import timedelta

# Setup Flask Application
app = Flask(__name__)

# Setup logging (penting untuk memonitor percakapan mencurigakan)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret Key untuk JWT
app.config['JWT_SECRET_KEY'] = 'secret-key-here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token kadaluarsa dalam 1 jam
jwt = JWTManager(app)

# Setup Rate Limiter (mencegah brute force)
limiter = Limiter(app, key_func=get_remote_address)

# Pengaturan otentikasi dua faktor (2FA)
totp = pyotp.TOTP('base32secret3232')

# Data Pengguna Dummy (gunakan database nyata untuk aplikasi nyata)
users = {}
user_2fa = {}

# Fungsi untuk validasi password (harus mengandung angka dan huruf besar)
def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    return True

# Rute untuk registrasi pengguna baru
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Membatasi registrasi per menit
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users:
        return jsonify({"message": "User already exists"}), 400

    if not validate_password(password):
        return jsonify({"message": "Password is too weak"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed_password

    # Setup 2FA untuk pengguna baru
    totp_uri = totp.provisioning_uri(username, issuer_name="SecureApp")
    user_2fa[username] = totp_uri

    return jsonify({"message": "User registered successfully!", "2fa_uri": totp_uri}), 201

# Rute untuk login pengguna
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Membatasi login per menit
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username not in users:
        return jsonify({"message": "User not found"}), 404

    stored_password = users[username]

    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"message": "Invalid credentials"}), 401

    # Setelah password valid, kirimkan kode 2FA
    otp_code = totp.now()  # Kirimkan OTP ke aplikasi 2FA pengguna (misalnya, Google Authenticator)

    return jsonify({
        "message": "Enter 2FA Code",
        "otp_code": otp_code,  # Simulasi, dalam aplikasi nyata kirimkan ini ke pengguna
        "username": username
    }), 200

# Rute untuk verifikasi 2FA
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    username = data.get("username")
    otp_code = data.get("otp_code")

    if username not in user_2fa:
        return jsonify({"message": "User not found"}), 404

    if not totp.verify(otp_code):
        return jsonify({"message": "Invalid 2FA code"}), 401

    # Generate JWT token setelah 2FA berhasil
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

# Rute untuk mengakses halaman yang dilindungi
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(message=f"Hello {current_user}, This is a protected route.")

# Keamanan tambahan dengan Rate Limiting untuk melindungi dari brute-force
@app.before_request
def before_request():
    if get_remote_address() == '127.0.0.1':  # Cek IP (Contoh: blokir IP tertentu)
        return jsonify(message="Access Forbidden"), 403

# Menggunakan HTTPS (Tentukan sertifikat SSL Anda)
if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
