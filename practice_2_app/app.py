from io import BytesIO
import secrets
import struct

from flask import Flask, render_template_string, request, send_file
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename


app = Flask(__name__)

MAGIC = b"P2AESCBC"
ITERATIONS = 600_000
HEADER_SIZE = len(MAGIC) + 4 + 16 + 40 + 16

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AES-CBC File Encryptor</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }
    form { border: 1px solid #ccc; border-radius: 10px; padding: 20px; margin: 20px 0; }
    label { display: block; margin: 12px 0 5px; }
    input, textarea, button { box-sizing: border-box; width: 100%; padding: 9px; }
    textarea { min-height: 110px; resize: vertical; }
    button { margin-top: 16px; cursor: pointer; }
    .error { color: #b00020; }
  </style>
</head>
<body>
  <h1>AES-256-CBC Encryptor</h1>
  <p>Encrypt text or any file, then download the resulting <code>.enc</code> file.</p>
  {% if error %}<p class="error">{{ error }}</p>{% endif %}

  <form action="/encrypt" method="post" enctype="multipart/form-data">
    <h2>Encrypt</h2>
    <label for="text">Text (used when no file is selected)</label>
    <textarea id="text" name="text"></textarea>
    <label for="plain_file">File</label>
    <input id="plain_file" name="file" type="file">
    <label for="encrypt_password">Password</label>
    <input id="encrypt_password" name="password" type="password" required>
    <button type="submit">Encrypt and download</button>
  </form>

  <form action="/decrypt" method="post" enctype="multipart/form-data">
    <h2>Decrypt</h2>
    <label for="encrypted_file">Encrypted .enc file</label>
    <input id="encrypted_file" name="file" type="file" required>
    <label for="decrypt_password">Password</label>
    <input id="decrypt_password" name="password" type="password" required>
    <button type="submit">Decrypt and download</button>
  </form>
</body>
</html>
"""


def derive_kek(password: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))


def derive_mac_key(data_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"practice-2-aes-cbc-hmac",
    ).derive(data_key)


def encrypt_bytes(data: bytes, password: str) -> bytes:
    data_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(data_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    kek = derive_kek(password, salt, ITERATIONS)
    wrapped_key = keywrap.aes_key_wrap(kek, data_key)
    body = MAGIC + struct.pack(">I", ITERATIONS) + salt + wrapped_key + iv + ciphertext

    signer = hmac.HMAC(derive_mac_key(data_key), hashes.SHA256())
    signer.update(body)
    return body + signer.finalize()


def decrypt_bytes(container: bytes, password: str) -> bytes:
    if len(container) < HEADER_SIZE + 16 + 32 or not container.startswith(MAGIC):
        raise ValueError("This is not a valid encrypted file.")

    position = len(MAGIC)
    iterations = struct.unpack(">I", container[position : position + 4])[0]
    position += 4
    salt = container[position : position + 16]
    position += 16
    wrapped_key = container[position : position + 40]
    position += 40
    iv = container[position : position + 16]
    position += 16
    ciphertext = container[position:-32]
    tag = container[-32:]

    if iterations < 100_000 or iterations > 5_000_000 or len(ciphertext) % 16:
        raise ValueError("The encrypted file has invalid parameters.")

    try:
        kek = derive_kek(password, salt, iterations)
        data_key = keywrap.aes_key_unwrap(kek, wrapped_key)
    except keywrap.InvalidUnwrap as exc:
        raise ValueError("Wrong password or damaged encrypted file.") from exc

    verifier = hmac.HMAC(derive_mac_key(data_key), hashes.SHA256())
    verifier.update(container[:-32])
    try:
        verifier.verify(tag)
    except InvalidSignature as exc:
        raise ValueError("Authentication failed: the file was modified.") from exc

    decryptor = Cipher(algorithms.AES(data_key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded_data) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError("The encrypted file has invalid padding.") from exc


@app.get("/")
def index():
    return render_template_string(PAGE, error=None)


@app.post("/encrypt")
def encrypt():
    password = request.form.get("password", "")
    uploaded = request.files.get("file")

    if not password:
        return render_template_string(PAGE, error="Enter a password."), 400

    if uploaded and uploaded.filename:
        data = uploaded.read()
        output_name = secure_filename(uploaded.filename) + ".enc"
    else:
        text = request.form.get("text", "")
        if not text:
            return render_template_string(PAGE, error="Enter text or select a file."), 400
        data = text.encode("utf-8")
        output_name = "message.txt.enc"

    encrypted = encrypt_bytes(data, password)
    return send_file(
        BytesIO(encrypted),
        as_attachment=True,
        download_name=output_name,
        mimetype="application/octet-stream",
    )


@app.post("/decrypt")
def decrypt():
    password = request.form.get("password", "")
    uploaded = request.files.get("file")

    if not password or not uploaded or not uploaded.filename:
        return render_template_string(PAGE, error="Select a file and enter its password."), 400

    try:
        decrypted = decrypt_bytes(uploaded.read(), password)
    except ValueError as exc:
        return render_template_string(PAGE, error=str(exc)), 400

    safe_name = secure_filename(uploaded.filename)
    output_name = safe_name[:-4] if safe_name.lower().endswith(".enc") else safe_name + ".decrypted"
    return send_file(BytesIO(decrypted), as_attachment=True, download_name=output_name)


if __name__ == "__main__":
    app.run(debug=True)
