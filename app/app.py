"""
ICARUS Lab — Deliberately Vulnerable Flask App
Every endpoint is intentionally broken to exercise a specific ICARUS module.
DO NOT run this in production or on a public network.
"""
import base64
import json
import os
import sqlite3
import time

import jwt as pyjwt
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# ─────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────
WEAK_SECRET = "secret"
DB_PATH = "/tmp/lab.db"

# ─────────────────────────────────────────────
# Bootstrap SQLite (in-memory style, file-based for persistence within container)
# ─────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    con.execute("INSERT OR IGNORE INTO users VALUES (1,'alice','alice123','user')")
    con.execute("INSERT OR IGNORE INTO users VALUES (2,'admin','admin123','admin')")
    con.commit()
    con.close()

init_db()

# ─────────────────────────────────────────────
# Root index — module map for testers
# ─────────────────────────────────────────────
MODULE_MAP = {
    "jwt_checker": {
        "POST /api/auth/login":        "Get a HS256 JWT (weak secret: 'secret')",
        "POST /api/auth/login-none":   "Get an alg=none JWT",
        "POST /api/auth/login-nonclaims": "JWT with no exp/iat/aud/iss/jti",
        "GET  /api/protected/profile": "Protected endpoint — send Bearer token",
        "GET  /api/protected/admin":   "Admin-only endpoint (role check skipped!)",
        "GET  /api/protected/kid":     "kid header path-traversal candidate",
    },
    "param_validator": {
        "POST /api/items":             "JSON body — no validation on any field",
        "POST /api/orders":            "Nested JSON — accepts any type / missing fields",
        "POST /api/search":            "Reflects 'query' field (XSS reflection target)",
        "POST /api/sqli":              "Concatenates 'name' into raw SQL (SQLi target)",
    },
    "http_verb_tester": {
        "ALL  /api/resource":          "GET only by design, but accepts PUT/DELETE/TRACE",
        "ALL  /api/strict":            "Correct Allow header, TRACE reflected",
    },
    "rate_limit_tester": {
        "POST /api/login-rate":        "No rate limiting on login (brute-force target)",
        "POST /api/otp":               "No rate limiting on OTP (50 requests, always 200)",
        "POST /api/limited-login":     "Has rate limiting after 10 requests (429)",
    },
    "sensitive_headers": {
        "GET  /api/headers/bad":       "Returns X-Powered-By, Server w/ version, debug headers",
        "GET  /api/headers/cookie":    "Set-Cookie without Secure/HttpOnly/SameSite",
        "GET  /api/headers/internal-ip": "X-Backend-Server with internal IP",
        "GET  /api/headers/missing-security": "All security headers absent",
        "GET  /api/headers/hsts":      "Correct HSTS present (baseline)",
    },
    "passive_error": {
        "GET  /api/error/stack":       "Returns Python stack trace in body",
        "GET  /api/error/sql":         "Returns raw SQL error",
        "GET  /api/error/php":         "Simulates PHP Warning in body",
        "GET  /api/error/verbose":     "Returns verbose Django-style debug page",
    },
    "auto_auth": {
        "POST /api/auth/refresh":      "Returns new access_token from refresh_token",
        "GET  /api/me":                "Returns 401 with WWW-Authenticate if no token",
    },
}

@app.route("/")
def index():
    return jsonify({"icarus_lab": True, "modules": MODULE_MAP})


# ═══════════════════════════════════════════════
# JWT CHECKER targets
# ═══════════════════════════════════════════════

def make_token(payload: dict, algorithm="HS256", secret=WEAK_SECRET) -> str:
    return pyjwt.encode(payload, secret, algorithm=algorithm)


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Issues a HS256 token signed with weak secret 'secret'.
    Deliberately missing nbf, aud, iss, jti — rich target for JwtChecker passive checks."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "alice")
    role = "admin" if username == "admin" else "user"
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "admin": (role == "admin"),
        "isAdmin": (role == "admin"),
        "exp": now + 3600,
        "iat": now,
        # deliberately missing: nbf, aud, iss, jti
    }
    token = make_token(payload)
    return jsonify({"access_token": token, "token_type": "Bearer"})


@app.route("/api/auth/login-none", methods=["POST"])
def auth_login_none():
    """Issues a token with alg=none (unsigned). The server will also accept it."""
    body = request.get_json(silent=True) or {}
    payload_bytes = json.dumps({"sub": body.get("username", "alice"), "role": "user"}).encode()
    # Manually craft alg=none token
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    pl = base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()
    token = f"{header}.{pl}."
    return jsonify({"access_token": token})


@app.route("/api/auth/login-nonclaims", methods=["POST"])
def auth_login_nonclaims():
    """Token with no standard claims (no exp, iat, aud, iss, jti, nbf)."""
    payload = {"sub": "alice", "data": "no-claims-at-all"}
    token = make_token(payload)
    return jsonify({"access_token": token})


def _decode_token(token: str) -> dict | None:
    """Accepts HS256 with weak secret AND alg=none (intentional vulnerability)."""
    try:
        # Try proper decode first
        return pyjwt.decode(token, WEAK_SECRET, algorithms=["HS256"])
    except Exception:
        pass
    try:
        # Accept alg=none — deliberately broken
        parts = token.split(".")
        if len(parts) == 3:
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        pass
    return None


def _get_bearer() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # Also check Cookie: token=...
    cookie_token = request.cookies.get("token")
    return cookie_token


@app.route("/api/protected/profile", methods=["GET"])
def protected_profile():
    token = _get_bearer()
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    claims = _decode_token(token)
    if not claims:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"user": claims.get("sub"), "role": claims.get("role")})


@app.route("/api/protected/admin", methods=["GET"])
def protected_admin():
    """Role check is performed on the UNVERIFIED payload claim — privilege escalation target."""
    token = _get_bearer()
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    # BUG: reads role from unverified decoded payload without re-signing check
    claims = _decode_token(token)
    if not claims:
        return jsonify({"error": "invalid token"}), 401
    if claims.get("role") == "admin" or claims.get("admin") is True or claims.get("isAdmin") is True:
        return jsonify({"admin_panel": True, "secret": "flag{jwt_privesc_worked}"})
    return jsonify({"error": "forbidden"}), 403


@app.route("/api/protected/kid", methods=["GET"])
def protected_kid():
    """Accepts kid in header, does path-join to load key file — path traversal target."""
    token = _get_bearer()
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    try:
        header_segment = token.split(".")[0]
        padded = header_segment + "=" * (4 - len(header_segment) % 4)
        header_json = json.loads(base64.urlsafe_b64decode(padded))
        kid = header_json.get("kid", "default")
        # BUG: path join without sanitization
        key_path = os.path.join("/app/keys", kid)
        try:
            with open(key_path, "rb") as f:
                key = f.read()
        except Exception:
            key = WEAK_SECRET.encode()
        claims = pyjwt.decode(token, key, algorithms=["HS256"])
        return jsonify({"ok": True, "claims": claims})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    """AutoAuth target: takes refresh_token, returns new access_token."""
    body = request.get_json(silent=True) or {}
    refresh = body.get("refresh_token", "")
    if not refresh:
        return jsonify({"error": "missing refresh_token"}), 400
    now = int(time.time())
    new_token = make_token({"sub": "alice", "role": "user", "exp": now + 3600, "iat": now})
    return jsonify({"access_token": new_token})


@app.route("/api/me", methods=["GET"])
def me():
    token = _get_bearer()
    if not token:
        return jsonify({"error": "unauthorized"}), 401, {
            "WWW-Authenticate": 'Bearer realm="icarus-lab"'
        }
    claims = _decode_token(token)
    if not claims:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"me": claims})


# ═══════════════════════════════════════════════
# PARAM VALIDATOR targets
# ═══════════════════════════════════════════════

@app.route("/api/items", methods=["POST"])
def create_item():
    """Accepts any JSON shape with no validation — structural/type/boundary mutations will get 200."""
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "expected JSON"}), 400
    # No validation at all — intentional
    return jsonify({"created": True, "item": body}), 201


@app.route("/api/orders", methods=["POST"])
def create_order():
    """Nested JSON — no type enforcement on quantity, price, user_id."""
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "expected JSON"}), 400
    return jsonify({"order_id": 42, "received": body}), 201


@app.route("/api/search", methods=["POST"])
def search():
    """XSS reflection target: echoes 'query' back into a JSON field without escaping."""
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")
    # Reflects raw user input — XSS detection target
    html_response = f"<html><body><h1>Results for: {query}</h1></body></html>"
    return Response(html_response, content_type="text/html")


@app.route("/api/sqli", methods=["POST"])
def sqli_endpoint():
    """Classic SQLi: raw string concatenation into a query."""
    body = request.get_json(silent=True) or {}
    name = body.get("name", "")
    con = sqlite3.connect(DB_PATH)
    try:
        # BUG: raw concatenation — SQLi target
        cur = con.execute(f"SELECT * FROM users WHERE username = '{name}'")
        rows = cur.fetchall()
        return jsonify({"results": rows})
    except Exception as e:
        # Returns DB error in body — also a PassiveError target
        return jsonify({"error": str(e), "query": f"SELECT * FROM users WHERE username = '{name}'"}), 500
    finally:
        con.close()


# ═══════════════════════════════════════════════
# HTTP VERB TESTER targets
# ═══════════════════════════════════════════════

@app.route("/api/resource", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"])
def resource():
    """Intended as GET-only but accepts all verbs — verb tester target.
    TRACE reflects all headers back (XST vulnerability).
    No Allow header returned."""
    method = request.method
    if method == "TRACE":
        # Reflects request headers — XST target
        body = "\r\n".join(f"{k}: {v}" for k, v in request.headers)
        return Response(body, content_type="message/http", status=200)
    if method == "OPTIONS":
        # Returns misleading Allow header
        return Response("", headers={"Allow": "GET, HEAD"}, status=200)
    return jsonify({"method": method, "accepted": True})


@app.route("/api/strict", methods=["GET", "HEAD", "OPTIONS"])
def strict_resource():
    """Properly restricted — only GET/HEAD/OPTIONS allowed. Correct Allow header."""
    if request.method == "OPTIONS":
        return Response("", headers={"Allow": "GET, HEAD, OPTIONS"}, status=200)
    return jsonify({"method": request.method, "data": "strict endpoint"})


# ═══════════════════════════════════════════════
# RATE LIMIT targets
# ═══════════════════════════════════════════════

_login_attempts: dict[str, int] = {}
_otp_attempts: dict[str, int] = {}

@app.route("/api/login-rate", methods=["POST"])
def login_rate():
    """No rate limiting — accepts infinite login attempts (brute-force target)."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password)).fetchone()
    con.close()
    if row:
        return jsonify({"success": True, "role": row[0]})
    return jsonify({"success": False}), 401


@app.route("/api/otp", methods=["POST"])
def otp():
    """OTP endpoint — no rate limiting, fixed OTP is '123456'."""
    body = request.get_json(silent=True) or {}
    otp_val = body.get("otp", "")
    if otp_val == "123456":
        return jsonify({"success": True, "message": "OTP verified"})
    return jsonify({"success": False, "message": "Invalid OTP"}), 200  # 200 even on failure — no lockout


@app.route("/api/limited-login", methods=["POST"])
def limited_login():
    """Has rate limiting: after 10 requests from same IP → 429."""
    ip = request.remote_addr or "unknown"
    _login_attempts[ip] = _login_attempts.get(ip, 0) + 1
    if _login_attempts[ip] > 10:
        return jsonify({"error": "Too Many Requests", "retry_after": 60}), 429
    body = request.get_json(silent=True) or {}
    return jsonify({"attempt": _login_attempts[ip], "received": body})


# ═══════════════════════════════════════════════
# SENSITIVE HEADERS targets
# ═══════════════════════════════════════════════

@app.route("/api/headers/bad", methods=["GET"])
def headers_bad():
    """Returns X-Powered-By, versioned Server, debug headers — SensitiveHeaderModule targets."""
    resp = jsonify({"data": "sensitive header disclosure test"})
    resp.headers["X-Powered-By"] = "PHP/8.1.0"
    resp.headers["X-AspNet-Version"] = "4.0.30319"
    resp.headers["X-Debug-Token"] = "abc123deadbeef"
    resp.headers["X-Debug-Token-Link"] = "http://localhost/_profiler/abc123"
    resp.headers["X-Runtime"] = "0.348291"
    resp.headers["X-Request-Id"] = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    resp.headers["Server"] = "Apache/2.4.51 (Unix)"
    return resp


@app.route("/api/headers/cookie", methods=["GET"])
def headers_cookie():
    """Set-Cookie without Secure, HttpOnly, or SameSite flags."""
    resp = jsonify({"login": "success"})
    resp.headers["Set-Cookie"] = "session=abc123; Path=/"  # Missing Secure, HttpOnly, SameSite
    return resp


@app.route("/api/headers/internal-ip", methods=["GET"])
def headers_internal_ip():
    """Leaks internal IP in a custom response header."""
    resp = jsonify({"data": "ok"})
    resp.headers["X-Backend-Server"] = "10.0.0.42"
    resp.headers["X-Forwarded-For"] = "192.168.1.100"
    return resp


@app.route("/api/headers/missing-security", methods=["GET"])
def headers_missing_security():
    """No HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy."""
    return jsonify({"data": "no security headers at all"})


@app.route("/api/headers/hsts", methods=["GET"])
def headers_hsts():
    """Correct HSTS present — baseline/control endpoint."""
    resp = jsonify({"data": "secure"})
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    return resp


# ═══════════════════════════════════════════════
# PASSIVE ERROR targets
# ═══════════════════════════════════════════════

@app.route("/api/error/stack", methods=["GET"])
def error_stack():
    """Returns a real Python stack trace — PassiveErrorModule target."""
    try:
        raise ValueError("Something went wrong in the database layer")
    except Exception:
        import traceback
        tb = traceback.format_exc()
        return Response(
            f"Internal Server Error\n\n{tb}",
            content_type="text/plain",
            status=500
        )


@app.route("/api/error/sql", methods=["GET"])
def error_sql():
    """Returns raw SQL error message."""
    return jsonify({
        "error": "OperationalError: near \"'\": syntax error",
        "query": "SELECT * FROM users WHERE id = '''",
        "hint": "Check your input"
    }), 500


@app.route("/api/error/php", methods=["GET"])
def error_php():
    """Simulates PHP warning in response body."""
    body = """<br />\n<b>PHP Warning</b>:  mysqli_fetch_assoc() expects parameter 1 to be mysqli_result, boolean given in <b>/var/www/html/index.php</b> on line <b>42</b><br />\n"""
    return Response(body, content_type="text/html", status=200)


@app.route("/api/error/verbose", methods=["GET"])
def error_verbose():
    """Simulates Django DEBUG=True style verbose error page."""
    body = """
    <html><head><title>OperationalError at /api/error/verbose</title></head>
    <body>
    <h1>OperationalError</h1>
    <pre>no such table: sessions</pre>
    <h2>Traceback</h2>
    <pre>
File "django/db/backends/utils.py", line 89, in execute
    return super().execute(sql, params)
File "django/db/backends/sqlite3/base.py", line 357, in execute
    return Database.Cursor.execute(self, query, params)
sqlite3.OperationalError: no such table: sessions
    </pre>
    <h2>Request information</h2>
    <p>GET /api/error/verbose</p>
    </body></html>
    """
    return Response(body, content_type="text/html", status=500)


# ─────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
