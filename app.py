from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
import qrcode
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyotp

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=False)
    ratchet_key = db.Column(db.LargeBinary(32), nullable=False)

# Key derivation function
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encryption function
def encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return base64.urlsafe_b64encode(iv + encryptor.update(message.encode()) + encryptor.finalize()).decode('utf-8')

# Decryption function
def decrypt(token, key):
    token = base64.urlsafe_b64decode(token)
    iv = token[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(token[16:]) + decryptor.finalize()).decode('utf-8')

# Initialize ratchet key
def initialize_ratchet_key():
    return os.urandom(32)

# Ratchet encryption
def ratchet_encrypt(message, ratchet_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ratchet_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return base64.urlsafe_b64encode(iv + encryptor.update(message.encode()) + encryptor.finalize()).decode('utf-8')

# Ratchet decryption
def ratchet_decrypt(token, ratchet_key):
    token = base64.urlsafe_b64decode(token)
    iv = token[:16]
    cipher = Cipher(algorithms.AES(ratchet_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(token[16:]) + decryptor.finalize()).decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_key = request.form.get('totp_key', '')

        user = User.query.filter_by(username=username).first()

        if user:
            # Login process
            salt = hashlib.sha256(username.encode()).digest()
            key = derive_key(password, salt)
            decrypted_password = decrypt(user.password, key)

            if decrypted_password == password:
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(totp_key):
                    session['username'] = username

                    # Encrypt the welcome message using ratchet
                    welcome_message = f"Welcome {username}, you are logged in!"
                    encrypted_message = ratchet_encrypt(welcome_message, user.ratchet_key)

                    # Redirect to a dashboard or home page with the encrypted message
                    return redirect(url_for('dashboard', encrypted_message=encrypted_message))
                else:
                    return "Invalid 2FA key"
            else:
                return "Invalid password"
        else:
            # Register process
            totp_secret = pyotp.random_base32()
            salt = hashlib.sha256(username.encode()).digest()
            key = derive_key(password, salt)
            encrypted_password = encrypt(password, key)

            ratchet_key = initialize_ratchet_key()

            new_user = User(username=username, password=encrypted_password, totp_secret=totp_secret, ratchet_key=ratchet_key)
            db.session.add(new_user)
            db.session.commit()

            # Display QR code for 2FA setup
            totp = pyotp.TOTP(totp_secret)
            qr_uri = totp.provisioning_uri(username, issuer_name="DummyWebsite")
            # return f'Registration successful! Scan this QR code with your authenticator app: {qr_uri}'
            def variable():
                for i in range(0,len(qr_uri)):
                    if qr_uri[i]=="=":
                        return i
            x=variable()
            text=qr_uri[x+1:x+33]
            return render_template('register.html', variable=text)

    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    encrypted_message = request.args.get('encrypted_message')
    if 'username' in session and encrypted_message:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            # Decrypt the welcome message using ratchet
            decrypted_message = ratchet_decrypt(encrypted_message, user.ratchet_key)
            return render_template('dashboard.html', decrypted_message=decrypted_message)
    return redirect('/')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=False,host='0.0.0.0')
