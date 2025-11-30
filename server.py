# server.py
# Minimal license server for Render deployment (free tier)
# Endpoints: /activate, /revoke, /status/<jti>, /heartbeat

import os
import time
import uuid
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import jwt  # PyJWT

# ---------------------------------------------------------
# Load private key (supports both raw PEM and base64)
# ---------------------------------------------------------

PRIVATE_KEY = None

# If the user pasted the raw PEM into Render Env "PRIVATE_KEY"
PRIVATE_KEY_PEM = os.environ.get("PRIVATE_KEY")
if PRIVATE_KEY_PEM:
    PRIVATE_KEY = PRIVATE_KEY_PEM.encode("utf-8")

# Or, if user provided base64-encoded PEM in PRIVATE_KEY_B64
if not PRIVATE_KEY:
    PRIVATE_KEY_B64 = os.environ.get("PRIVATE_KEY_B64")
    if PRIVATE_KEY_B64:
        try:
            PRIVATE_KEY = base64.b64decode(PRIVATE_KEY_B64)
        except Exception:
            raise RuntimeError("PRIVATE_KEY_B64 exists but is not valid base64")

if not PRIVATE_KEY:
    raise RuntimeError("Missing PRIVATE_KEY or PRIVATE_KEY_B64 environment variable (set raw PEM or base64(private.pem))")

# ---------------------------------------------------------
# Config
# ---------------------------------------------------------

JWT_ALGO = "RS256"
DB_PATH = "licenses.db"

app = Flask(__name__)

# ---------------------------------------------------------
# Database init
# ---------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses (
                    id TEXT PRIMARY KEY,
                    license_key TEXT,
                    hwid TEXT,
                    user TEXT,
                    issued_at INTEGER,
                    expires_at INTEGER,
                    revoked INTEGER DEFAULT 0,
                    last_seen INTEGER DEFAULT 0
                )''')
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------
# Utilities
# ---------------------------------------------------------

def sign_license(payload):
    return jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGO)

# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

@app.route("/")
def index():
    return jsonify({"ok": True, "service": "license-server"})

# --------------------- ACTIVATE ---------------------------

@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    lic_key = data.get("license_key")
    hwid = data.get("hwid")
    user = data.get("user", "")
    duration = int(data.get("duration_days", 365))

    if not lic_key or not hwid:
        return jsonify({"error": "license_key and hwid required"}), 400

    lic_id = str(uuid.uuid4())
    issued = int(time.time())
    expires = issued + duration * 24 * 3600

    payload = {
        "jti": lic_id,
        "sub": lic_key,
        "user": user,
        "hwid": hwid,
        "iat": issued,
        "exp": expires,
        "features": {"bot": True}
    }
    token = sign_license(payload)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (id, license_key, hwid, user, issued_at, expires_at) VALUES (?,?,?,?,?,?)",
        (lic_id, lic_key, hwid, user, issued, expires)
    )
    conn.commit()
    conn.close()

    return jsonify({"token": token, "jti": lic_id, "expires_at": expires})

# --------------------- REVOKE -----------------------------

@app.route("/revoke", methods=["POST"])
def revoke():
    data = request.json or {}
    jti = data.get("jti")
    if not jti:
        return jsonify({"error":"jti required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE licenses SET revoked=1 WHERE id=?", (jti,))
    conn.commit()
    updated = c.rowcount
    conn.close()

    if updated == 0:
        return jsonify({"error":"not found"}), 404

    return jsonify({"revoked": True})

# --------------------- STATUS -----------------------------

@app.route("/status/<jti>", methods=["GET"])
def status(jti):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, license_key, hwid, issued_at, expires_at, revoked, last_seen FROM licenses WHERE id=?", (jti,))
    r = c.fetchone()
    conn.close()

    if not r:
        return jsonify({"error":"not found"}), 404

    return jsonify({
        "id": r[0],
        "license_key": r[1],
        "hwid": r[2],
        "issued_at": r[3],
        "expires_at": r[4],
        "revoked": bool(r[5]),
        "last_seen": r[6]
    })

# --------------------- HEARTBEAT --------------------------

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.json or {}
    token = data.get("token")

    if not token:
        return jsonify({"error":"token required"}), 400

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")
    except Exception:
        return jsonify({"error":"invalid token"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT revoked, expires_at FROM licenses WHERE id=?", (jti,))
    r = c.fetchone()

    if not r:
        conn.close()
        return jsonify({"error":"not found"}), 404

    revoked, expires_at = r
    now = int(time.time())

    c.execute("UPDATE licenses SET last_seen=? WHERE id=?", (now, jti))
    conn.commit()
    conn.close()

    if revoked:
        return jsonify({"revoked": True})
    if now > expires_at:
        return jsonify({"expired": True})
    return jsonify({"ok": True, "expires_at": expires_at})

# ---------------------------------------------------------
# Run (local only)
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
