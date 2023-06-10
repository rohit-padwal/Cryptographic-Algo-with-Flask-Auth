import hashlib
import io

import secrets

from Crypto.Protocol.KDF import HKDF
from cryptography.exceptions import InvalidSignature
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session, request, send_file
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError

from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app, db, login_manager, bcrypt
from models import User
from forms import login_form, register_form
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import padding

from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import os
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA as CryptoRSA

from Crypto.Random import get_random_bytes

curr_user = ""
curr_pw = ""


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app = create_app()


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    return render_template("index.html", title="Home")


@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if check_password_hash(user.pwd, form.pwd.data):
                login_user(user)

                return redirect(url_for('index'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash(e, "danger")

    return render_template("auth.html",
                           form=form,
                           text="Login",
                           title="Login",
                           btn_action="Login"
                           )


# Register route
@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    form = register_form()
    if form.validate_on_submit():
        try:
            email = form.email.data
            pwd = form.pwd.data
            username = form.username.data

            newuser = User(
                username=username,
                email=email,
                pwd=bcrypt.generate_password_hash(pwd),
            )

            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
            return redirect(url_for("login"))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")
    return render_template("auth.html",
                           form=form,
                           text="Create account",
                           title="Register",
                           btn_action="Register account"
                           )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/TDES/", methods=("GET", "POST"), strict_slashes=False)
def TDES():
    return render_template("tdes.html")
# generate a key and an initialization vector

key_for_tdes=os.urandom(24)
iv_for_tdes=os.urandom(8)

# encryption code
@app.route('/encryptTDES', methods=['POST'])
def encryptTDES():


    # get the input file from the request
    input_file = request.files['file']

    # encrypt the input file
    encrypted_file_path = 'encrypted_file.txt'
    encrypt_file_for_tdes(key_for_tdes, iv_for_tdes, input_file, encrypted_file_path)

    # download the encrypted file
    return send_file(encrypted_file_path, as_attachment=True)


def encrypt_file_for_tdes(key, iv, input_file, output_file_path):
    # create a DES3 object with the key and IV
    des3 = DES3.new(key, DES3.MODE_CBC, iv)

    # read the contents of the input file
    input_data = input_file.read()

    # pad the input data to a multiple of 8 bytes
    padding_length = 8 - len(input_data) % 8
    if padding_length > 0:
        padded_input_data = input_data + bytes([padding_length] * padding_length)

    # encrypt the padded input data and write it to the output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(des3.encrypt(padded_input_data))


# decryption code
@app.route('/decryptTDES', methods=['POST'])
def decryptTDES():
    # generate a key and an initialization vector
    key = os.urandom(24)
    iv = os.urandom(8)

    # get the input file from the request
    input_file = request.files['file']

    # decrypt the input file
    decrypted_file_path = 'decrypted_file.txt'
    decrypt_file_for_3des(key_for_tdes, iv_for_tdes, input_file, decrypted_file_path)

    # download the decrypted file
    return send_file(decrypted_file_path, as_attachment=True)


def decrypt_file_for_3des(key, iv, input_file, output_file_path):
    # create a DES3 object with the key and IV
    des3 = DES3.new(key, DES3.MODE_CBC, iv)

    # read the encrypted data from the input file
    encrypted_data = input_file.read()

    # decrypt the encrypted data
    decrypted_data = des3.decrypt(encrypted_data)

    # remove the padding from the decrypted data
    padding_length = decrypted_data[-1]
    if padding_length > 0:
        unpadded_decrypted_data = decrypted_data[:-padding_length]

    # write the decrypted data to the output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(unpadded_decrypted_data)


@app.route("/AES1/", methods=("GET", "POST"), strict_slashes=False)
def AES1():
    return render_template("aes1.html")


app.config['UPLOAD_FOLDER'] = './static'


@app.route("/encryptAES1", methods=["POST"])
def encryptAES1():
    key = request.form['key'].encode('utf-8')
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    chunk_size = 64 * 1024
    output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_' + filename)

    with open(filepath, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            cipher = AES.new(key, AES.MODE_EAX)
            outfile.write(cipher.nonce)
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                ciphertext, tag = cipher.encrypt_and_digest(chunk)
                outfile.write(ciphertext)

    return send_file(output_file, as_attachment=True)


@app.route("/decryptAES1", methods=["POST"])
def decryptAES1():
    key = request.form['key'].encode('utf-8')
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    chunk_size = 64 * 1024
    output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + filename)

    with open(filepath, 'rb') as infile:
        nonce = infile.read(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                plaintext = cipher.decrypt(chunk)
                outfile.write(plaintext)

    return send_file(output_file, as_attachment=True)


@app.route("/RSA/", methods=("GET", "POST"), strict_slashes=False)
def RSA():
    return render_template("rsa.html")


RSA_key = CryptoRSA.generate(2048)

RSA_private_key = RSA_key.export_key()
with open('private_key.pem', 'wb') as f:
    f.write(RSA_private_key)

RSA_public_key = RSA_key.publickey().export_key()
with open('public_key.pem', 'wb') as f:
    f.write(RSA_public_key)


def encrypt_file_for_RSA(file, public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = CryptoRSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(public_key)

    encrypted_data = cipher.encrypt(file.read())

    return encrypted_data


def decrypt_file_for_RSA(file, private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = CryptoRSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(private_key)

    decrypted_data = cipher.decrypt(file.read())

    return decrypted_data


@app.route('/encryptRSA', methods=['POST'])
def encryptRSA():
    # Encrypt file with public key
    file = request.files['file']
    encrypted_data = encrypt_file_for_RSA(file, 'public_key.pem')
    return send_file(io.BytesIO(encrypted_data), attachment_filename=f'encrypted_{file.filename}', as_attachment=True)


@app.route('/decryptRSA', methods=['POST'])
def decryptRSA():
    # Decrypt file with private key
    file = request.files['file']
    decrypted_data = decrypt_file_for_RSA(file, 'private_key.pem')
    return send_file(io.BytesIO(decrypted_data), attachment_filename=f'decrypted_{file.filename}', as_attachment=True)


@app.route("/SHA2/", methods=("GET", "POST"), strict_slashes=False)
def SHA2():
    return render_template("sha.html")


@app.route('/encryptSHA', methods=['POST'])
def encryptSHA():
    file = request.files['file']
    filename = file.filename
    sha = hashlib.sha256()
    chunk_size = 4096
    with open(filename, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            sha.update(data)
    file.seek(0)
    with open(f"encrypted_{filename}", 'wb') as f:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            f.write(sha.digest() + data)
    return send_file(f"encrypted_{filename}")


@app.route('/decryptSHA', methods=['POST'])
def decryptSHA():
    file = request.files['file']
    filename = file.filename
    sha = hashlib.sha256()
    chunk_size = 4096
    with open(filename, 'rb') as f:
        while True:
            data = f.read(chunk_size + 32)
            if not data:
                break
            sha.update(data[32:])
            if sha.digest() == data[:32]:
                with open(f"decrypted_{filename}", 'wb') as f_out:
                    f_out.write(data[32:])
                return send_file(f"decrypted_{filename}")
    return "Error: decryption failed"

@app.route('/compareHash', methods=['POST'])
def compare_hashes():
    file1 = request.files['file1']
    file2 = request.files['file2']
    hash1 = hashlib.sha256()
    hash2 = hashlib.sha256()
    lst=[]
    while True:
        data1 = file1.read(1024)
        data2 = file2.read(1024)
        if not data1 and not data2:
            break
        hash1.update(data1)
        hash2.update(data2)
        lst.append(hash1.hexdigest())
        lst.append(hash2.hexdigest())

    return render_template('compSha.html', lst=lst)


@app.route("/DH/", methods=("GET", "POST"), strict_slashes=False)
def DH():
    return render_template("dh.html")


@app.route("/key-exchange", methods=["POST"])
def key_exchange():
    # Generate a DH private key
    private_key = dh.generate_private_key(key_size=2048)
    # Get the public key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key


# Generate a Diffie-Hellman key pair
parameters_dh = dh.generate_parameters(generator=2, key_size=2048)
private_key_dh = parameters_dh.generate_private_key()
public_key_dh = private_key_dh.public_key()

@app.route("/encryptDH", methods=["POST"])
def encryptDH():
    # Receive the file from the client
    file = request.files["file"]

    # Generate a shared secret key using Diffie-Hellman key exchange
    client_public_key = dh.DHPublicKey.from_encoded_point(parameters_dh, public_key_dh.encode())
    shared_key = private_key_dh.exchange(client_public_key)

    # Derive an encryption key from the shared secret key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256(), length=32, salt=salt, iterations=100000)
    encryption_key = kdf.derive(shared_key)

    # Encrypt the file
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file.read()) + encryptor.finalize()

    # Concatenate the IV and encrypted data and save to a file
    encrypted_file_data = iv + encrypted_data
    encrypted_file = open(file.filename + ".enc", "wb")
    encrypted_file.write(encrypted_file_data)
    encrypted_file.close()

    # Return the encrypted file to the client
    return send_file(file.filename + ".enc", as_attachment=True)


@app.route("/decryptDH", methods=["POST"])
def decryptDH():
    # Receive the encrypted file from the client
    encrypted_file = request.files["file"]

    # Generate a shared secret key using Diffie-Hellman key exchange
    client_public_key = dh.DHPublicKey.from_encoded_point(parameters_dh, public_key_dh.encode())
    shared_key = private_key_dh.exchange(client_public_key)

    # Derive an encryption key from the shared secret key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256(), length=32, salt=salt, iterations=100000)
    encryption_key = kdf.derive(shared_key)

    # Decrypt the file
    encrypted_file_data = encrypted_file.read()
    iv = encrypted_file_data[:16]
    encrypted_data = encrypted_file_data[16:]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Save the decrypted data to a file
    decrypted_file = open(encrypted_file.filename[:-4], "wb")
    decrypted_file.write(decrypted_data)
    decrypted_file.close()

    # Return the decrypted file to the client
    return send_file(encrypted_file.filename[:-4], as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
