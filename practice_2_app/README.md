# Practice 2 - AES-CBC application

A minimal Flask application that encrypts text or arbitrary files with AES-256-CBC. It uses PKCS#7 padding, a random key/IV/salt, password-based AES key wrapping, and HMAC-SHA-256 authentication.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

## Important

- Keep the password: decryption is impossible without it.
- The app does not save uploaded files on the server; it returns the result as a download.
