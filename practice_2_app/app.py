from io import BytesIO
import os
from pathlib import Path
import secrets
import struct
from tempfile import TemporaryDirectory

from flask import Flask, render_template_string, request, send_file
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename


app = Flask(__name__)

MAGIC = b"P2AESCBC"
FORMAT_VERSION = 1
ALGORITHM_AES_256_CBC = 1
KDF_PBKDF2_HMAC_SHA256 = 1
ITERATIONS = 600_000
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 5_000_000
AES_BLOCK_SIZE_BITS = 128
AES_BLOCK_SIZE_BYTES = AES_BLOCK_SIZE_BITS // 8
HMAC_TAG_SIZE = 32
CONTAINER_HEADER = struct.Struct(">8sBBBI16s40s16s")

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

    padder = padding.PKCS7(AES_BLOCK_SIZE_BITS).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(data_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    kek = derive_kek(password, salt, ITERATIONS)
    wrapped_key = keywrap.aes_key_wrap(kek, data_key)
    header = CONTAINER_HEADER.pack(
        MAGIC,
        FORMAT_VERSION,
        ALGORITHM_AES_256_CBC,
        KDF_PBKDF2_HMAC_SHA256,
        ITERATIONS,
        salt,
        wrapped_key,
        iv,
    )
    body = header + ciphertext

    signer = hmac.HMAC(derive_mac_key(data_key), hashes.SHA256())
    signer.update(body)
    return body + signer.finalize()


def decrypt_bytes(container: bytes, password: str) -> bytes:
    minimum_size = CONTAINER_HEADER.size + AES_BLOCK_SIZE_BYTES + HMAC_TAG_SIZE
    if len(container) < minimum_size:
        raise ValueError("This is not a valid encrypted file.")

    (
        magic,
        version,
        algorithm_id,
        kdf_id,
        iterations,
        salt,
        wrapped_key,
        iv,
    ) = CONTAINER_HEADER.unpack_from(container)

    if magic != MAGIC:
        raise ValueError("This is not a valid encrypted file.")
    if version != FORMAT_VERSION:
        raise ValueError("The encrypted file uses an unsupported format version.")
    if algorithm_id != ALGORITHM_AES_256_CBC:
        raise ValueError("The encrypted file uses an unsupported encryption algorithm.")
    if kdf_id != KDF_PBKDF2_HMAC_SHA256:
        raise ValueError("The encrypted file uses an unsupported password KDF.")

    ciphertext = container[CONTAINER_HEADER.size : -HMAC_TAG_SIZE]
    tag = container[-HMAC_TAG_SIZE:]

    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError("The encrypted file has invalid KDF parameters.")
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE_BYTES:
        raise ValueError("The encrypted file has invalid parameters.")

    try:
        kek = derive_kek(password, salt, iterations)
        data_key = keywrap.aes_key_unwrap(kek, wrapped_key)
    except keywrap.InvalidUnwrap as exc:
        raise ValueError("Wrong password or damaged encrypted file.") from exc

    verifier = hmac.HMAC(derive_mac_key(data_key), hashes.SHA256())
    verifier.update(container[:-HMAC_TAG_SIZE])
    try:
        verifier.verify(tag)
    except InvalidSignature as exc:
        raise ValueError("Authentication failed: the file was modified.") from exc

    decryptor = Cipher(algorithms.AES(data_key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    try:
        return unpadder.update(padded_data) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError("The encrypted file has invalid padding.") from exc


def write_verified_file(destination: Path, data: bytes) -> None:
    """Write a new file atomically and verify its complete contents."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Output file already exists: {destination.name}")

    temporary = destination.with_name(
        f".{destination.name}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        if temporary.read_bytes() != data:
            raise OSError("The temporary output file could not be verified.")

        temporary.replace(destination)
        if destination.read_bytes() != data:
            destination.unlink(missing_ok=True)
            raise OSError("The completed output file could not be verified.")
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def encrypt_file(
    input_path: Path, output_path: Path, password: str, *, remove_source: bool = True
) -> Path:
    """Encrypt a file and remove the source only after verified output exists."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different.")

    encrypted = encrypt_bytes(input_path.read_bytes(), password)
    write_verified_file(output_path, encrypted)
    if remove_source:
        input_path.unlink()
    return output_path


def decrypt_file(
    input_path: Path, output_path: Path, password: str, *, remove_source: bool = True
) -> Path:
    """Decrypt a file and remove the container only after verified output exists."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different.")

    decrypted = decrypt_bytes(input_path.read_bytes(), password)
    write_verified_file(output_path, decrypted)
    if remove_source:
        input_path.unlink()
    return output_path


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
        input_name = secure_filename(uploaded.filename) or "upload.bin"
        output_name = input_name + ".enc"
    else:
        text = request.form.get("text", "")
        if not text:
            return render_template_string(PAGE, error="Enter text or select a file."), 400
        data = text.encode("utf-8")
        input_name = "message.txt"
        output_name = "message.txt.enc"

    try:
        with TemporaryDirectory(prefix="practice-2-encrypt-") as directory:
            workspace = Path(directory)
            input_path = workspace / input_name
            output_path = workspace / output_name
            write_verified_file(input_path, data)
            encrypt_file(input_path, output_path, password)
            encrypted = output_path.read_bytes()
    except OSError:
        return render_template_string(
            PAGE, error="The encrypted output could not be written safely."
        ), 500

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

    safe_name = secure_filename(uploaded.filename) or "encrypted.enc"
    output_name = (
        safe_name[:-4]
        if safe_name.lower().endswith(".enc")
        else safe_name + ".decrypted"
    )

    try:
        with TemporaryDirectory(prefix="practice-2-decrypt-") as directory:
            workspace = Path(directory)
            input_path = workspace / safe_name
            output_path = workspace / output_name
            write_verified_file(input_path, uploaded.read())
            decrypt_file(input_path, output_path, password)
            decrypted = output_path.read_bytes()
    except ValueError as exc:
        return render_template_string(PAGE, error=str(exc)), 400
    except OSError:
        return render_template_string(
            PAGE, error="The restored output could not be written safely."
        ), 500

    return send_file(BytesIO(decrypted), as_attachment=True, download_name=output_name)


if __name__ == "__main__":
    app.run(debug=True)
