from flask import Flask, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import os, io, mimetypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
UPLOAD_FOLDER = "uploads"
KEY_FILE = "key.key"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_key():
    if not os.path.exists(KEY_FILE):
        raise RuntimeError("Encryption key not found. Generate key.key first.")
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext

def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Encrypted blob too small")
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route("/")
def index():
    files = []
    for f in sorted(os.listdir(UPLOAD_FOLDER)):
        if f.endswith(".enc"):
            files.append(f[:-4])
    msg = request.args.get("msg", "")
    return render_template("index.html", files=files, msg=msg)

@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        return redirect(url_for("index", msg="No file selected"))
    filename = secure_filename(uploaded.filename)
    data = uploaded.read()
    key = load_key()
    enc = encrypt_bytes(data, key)
    outpath = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    with open(outpath, "wb") as fh:
        fh.write(enc)
    return redirect(url_for("index", msg="File uploaded and encrypted successfully"))

@app.route("/download/<path:name>")
def download(name):
    safe = secure_filename(name)
    enc_path = os.path.join(UPLOAD_FOLDER, safe + ".enc")
    if not os.path.exists(enc_path):
        return redirect(url_for("index", msg="File not found"))
    key = load_key()
    blob = open(enc_path, "rb").read()
    try:
        plain = decrypt_bytes(blob, key)
    except Exception as e:
        return redirect(url_for("index", msg="Decryption failed"))
    mimetype = mimetypes.guess_type(safe)[0] or "application/octet-stream"
    return send_file(io.BytesIO(plain), download_name=safe, as_attachment=True, mimetype=mimetype)

@app.route("/delete/<path:name>", methods=["POST"])
def delete(name):
    safe = secure_filename(name)
    enc_path = os.path.join(UPLOAD_FOLDER, safe + ".enc")
    if os.path.exists(enc_path):
        os.remove(enc_path)
        return redirect(url_for("index", msg="File deleted"))
    return redirect(url_for("index", msg="File not found"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
from flask import Flask, render_template, request, redirect, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load AES key
with open("key.key", "rb") as f:
    KEY = f.read()

# Encrypt file
def encrypt_file(file_path):
    cipher = AES.new(KEY, AES.MODE_CBC)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    enc_path = file_path + ".enc"
    with open(enc_path, "wb") as f:
        f.write(cipher.iv + ct_bytes)
    os.remove(file_path)
    return enc_path

# Decrypt file
def decrypt_file(enc_path):
    with open(enc_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    dec_path = enc_path.replace(".enc", "")
    with open(dec_path, "wb") as f:
        f.write(pt)
    return dec_path

@app.route("/")
def index():
    files = [f.replace(".enc", "") for f in os.listdir(UPLOAD_FOLDER) if f.endswith(".enc")]
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        encrypt_file(filepath)
    return redirect("/")

@app.route("/download/<filename>")
def download(filename):
    enc_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    dec_path = decrypt_file(enc_path)
    return send_file(dec_path, as_attachment=True)

@app.route("/delete/<filename>", methods=["POST"])
def delete(filename):
    enc_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    if os.path.exists(enc_path):
        os.remove(enc_path)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
