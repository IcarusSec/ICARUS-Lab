# ICARUS Lab

Deliberately vulnerable Flask app for testing every ICARUS Burp extension module.

**Target URL (in Burp):** `http://localhost:8888`

## Start

```bash
cd ~/icarus-lab
docker compose up --build -d
```

Check it's alive:
```bash
curl http://localhost:8888/health
```

Full module map:
```bash
curl http://localhost:8888/ | python3 -m json.tool
```

Stop:
```bash
docker compose down
```

---

## Module Test Guide

### JWT Checker

**Step 1 — get a weak HS256 token (passive hits: WEAK_MAC, MISSING_NBF, MISSING_AUD, MISSING_ISS, MISSING_JTI, MISSING_HSTS)**
```
POST /api/auth/login HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"username": "alice", "password": "alice123"}
```
Copy the `access_token`. Send to ICARUS scanner.

**Step 2 — active tests: privilege escalation (role claim tampering)**
```
GET /api/protected/admin HTTP/1.1
Host: localhost:8888
Authorization: Bearer <token_from_step1>
```
ICARUS will tamper the `role`, `admin`, `isAdmin` claims and re-send. `/api/protected/admin` accepts them → `ACTIVE_HIT_tamper-*` findings.

**Step 3 — alg=none bypass**
```
POST /api/auth/login-none HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"username": "alice"}
```
Token returned has `alg=none`. ICARUS passive check: `ALG_NONE` (CRITICAL). Then scan `GET /api/protected/profile` with it — will get 200.

**Step 4 — no standard claims**
```
POST /api/auth/login-nonclaims HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{}
```
Expect findings: `MISSING_EXP`, `MISSING_IAT`, `MISSING_NBF`, `MISSING_AUD`, `MISSING_ISS`, `MISSING_JTI`.

**Step 5 — kid path traversal**
```
GET /api/protected/kid HTTP/1.1
Host: localhost:8888
Authorization: Bearer <tampered_token_with_kid_../../dev/null>
```
ICARUS injects `kid: ../../../../../../dev/null` into the header and sends to this endpoint.

---

### ParamValidator

**Endpoint 1 — no validation at all (structural + type + boundary hits)**
```
POST /api/items HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"name": "widget", "price": 9.99, "quantity": 10, "active": true}
```
Send to ICARUS. It will try: null values, field removal, type swaps, long strings, XSS payloads, SQLi. All get 201 → `Missing Input Validation` findings.

**Endpoint 2 — XSS reflection**
```
POST /api/search HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"query": "test"}
```
ICARUS injects `<script>alert(1)</script>` into `query`. The response body contains the raw string → `STRING_XSS` finding.

**Endpoint 3 — SQLi (also triggers passive error)**
```
POST /api/sqli HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"name": "alice"}
```
ICARUS sends `' OR '1'='1`. On error, the response includes the raw SQL query → `STRING_SQLI` finding + possible PassiveError finding.

---

### HTTP Verb Tester

**Target 1 — accepts all verbs, TRACE reflects headers**
```
GET /api/resource HTTP/1.1
Host: localhost:8888
```
Send to ICARUS. It will try GET/HEAD/OPTIONS/TRACE/PUT/DELETE.
- TRACE returns all request headers → `TRACE_REFLECTION` (HIGH)
- PUT/DELETE get 200 → `ACCEPTED_METHOD` findings
- OPTIONS returns `Allow: GET, HEAD` but PUT was accepted → `ALLOW_MISMATCH`

**Target 2 — correctly restricted (control)**
```
GET /api/strict HTTP/1.1
Host: localhost:8888
```
Only GET/HEAD/OPTIONS accepted. No findings expected (clean baseline).

---

### Rate Limit Tester

**Target 1 — no rate limit on login**
```
POST /api/login-rate HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"username": "admin", "password": "wrong"}
```
Send to ICARUS Rate Limit module (50 requests). All return 200 or 401 — no 429 → `NO_RATE_LIMIT` finding.

**Target 2 — OTP with no lockout**
```
POST /api/otp HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"otp": "000000"}
```
50 blasts, all 200, no lockout. OTP `123456` succeeds. Demonstrates brute-force surface.

**Target 3 — rate limit exists (control)**
```
POST /api/limited-login HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"username": "test"}
```
After 10 requests → 429. ICARUS should detect the threshold and report `RATE_LIMIT_ENFORCED`.

---

### Sensitive Headers

**Target 1 — version + debug headers**
```
GET /api/headers/bad HTTP/1.1
Host: localhost:8888
```
Expect findings: `VERSION_DISCLOSURE` (X-Powered-By, Server w/ version), `DEBUG_HEADER` (X-Debug-Token, X-Runtime, X-Request-Id).

**Target 2 — cookie flags**
```
GET /api/headers/cookie HTTP/1.1
Host: localhost:8888
```
Expect: `COOKIE_MISSING_SECURE`, `COOKIE_MISSING_HTTPONLY`, `COOKIE_MISSING_SAMESITE`.

**Target 3 — internal IP leak**
```
GET /api/headers/internal-ip HTTP/1.1
Host: localhost:8888
```
Expect: `INTERNAL_IP_LEAK` from `X-Backend-Server: 10.0.0.42`.

**Target 4 — all security headers missing**
```
GET /api/headers/missing-security HTTP/1.1
Host: localhost:8888
```
Expect: `MISSING_HSTS`, `MISSING_CSP`, `MISSING_XCTO`, `MISSING_XFO`, `MISSING_RP`, `MISSING_PP`.

**Target 5 — clean baseline**
```
GET /api/headers/hsts HTTP/1.1
Host: localhost:8888
```
All headers present. No findings expected.

---

### Passive Error

**Target 1 — Python stack trace in body**
```
GET /api/error/stack HTTP/1.1
Host: localhost:8888
```
Response contains `Traceback (most recent call last)` → PassiveError finding.

**Target 2 — raw SQL error**
```
GET /api/error/sql HTTP/1.1
Host: localhost:8888
```
Response contains `OperationalError` and raw query → PassiveError finding.

**Target 3 — PHP warning simulation**
```
GET /api/error/php HTTP/1.1
Host: localhost:8888
```
Response body contains `PHP Warning` → PassiveError finding.

**Target 4 — Django-style verbose debug page**
```
GET /api/error/verbose HTTP/1.1
Host: localhost:8888
```
Django OperationalError with traceback in HTML → PassiveError finding.

---

### AutoAuth

**Step 1 — configure ICARUS AutoAuth with:**
- Token endpoint: `POST /api/auth/login`
- Body: `{"username": "alice", "password": "alice123"}`
- Token path: `$.access_token`
- Injection: `Authorization: Bearer {{token}}`

**Step 2 — send a request to a protected endpoint:**
```
GET /api/me HTTP/1.1
Host: localhost:8888
```
Without a token: 401. AutoAuth should auto-inject the token and retry → 200.

**Refresh token flow:**
```
POST /api/auth/refresh HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"refresh_token": "dummy-refresh-token"}
```
Returns a new `access_token`. Use as the AutoAuth refresh endpoint.

---

## Notes

- The lab runs on port **8888** — set Burp's target scope to `http://localhost:8888`.
- The SQLite DB resets on container restart.
- Rate limit counters are in-memory — restart the container to reset them.
- All findings are intentional. This is a controlled environment, not a real application.
