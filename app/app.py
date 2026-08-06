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
from flask import Flask, jsonify, request, Response, render_template_string

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
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICARUS Lab</title>
<style>
  :root {
    --bg: #12131a;
    --surface: #1c1e2b;
    --border: #2a2d3e;
    --accent: #ff6633;
    --accent2: #5e9dd9;
    --text: #d0d4e8;
    --muted: #6b7094;
    --green: #4ade80;
    --yellow: #facc15;
    --red: #f87171;
    --radius: 8px;
    --font: 'Segoe UI', system-ui, sans-serif;
    --mono: 'Cascadia Code', 'Fira Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 18px 32px;
    display: flex;
    align-items: center;
    gap: 14px;
  }
  header .logo { font-size: 1.5rem; font-weight: 800; color: var(--accent); letter-spacing: -0.5px; }
  header .sub  { font-size: 0.85rem; color: var(--muted); }
  header .badge {
    margin-left: auto;
    background: #3a1a0a;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .layout { display: grid; grid-template-columns: 220px 1fr 360px; height: calc(100vh - 61px); }

  /* Sidebar */
  nav {
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 20px 0;
    overflow-y: auto;
  }
  nav .section-label {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--muted);
    text-transform: uppercase;
    padding: 0 16px 8px;
  }
  nav a {
    display: block;
    padding: 9px 16px;
    color: var(--text);
    text-decoration: none;
    font-size: 0.88rem;
    border-left: 3px solid transparent;
    transition: all 0.15s;
  }
  nav a:hover, nav a.active {
    background: rgba(255,102,51,0.08);
    border-left-color: var(--accent);
    color: #fff;
  }
  nav a .dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    margin-right: 8px;
    vertical-align: middle;
  }

  /* Main */
  main { overflow-y: auto; padding: 28px 32px; }
  .module { display: none; }
  .module.active { display: block; }

  .module-title {
    font-size: 1.25rem;
    font-weight: 700;
    margin-bottom: 4px;
  }
  .module-desc {
    font-size: 0.85rem;
    color: var(--muted);
    margin-bottom: 24px;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 16px;
    overflow: hidden;
  }
  .card-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
  }
  .method {
    font-family: var(--mono);
    font-size: 0.75rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    background: #1a2a1a;
    color: var(--green);
  }
  .method.POST { background: #1a1f2a; color: var(--accent2); }
  .method.GET  { background: #1a2a1a; color: var(--green); }
  .method.ALL  { background: #2a1a2a; color: var(--yellow); }
  .endpoint-path { font-family: var(--mono); font-size: 0.85rem; color: #fff; }
  .vuln-tag {
    margin-left: auto;
    font-size: 0.7rem;
    color: var(--accent);
    background: rgba(255,102,51,0.12);
    border: 1px solid rgba(255,102,51,0.3);
    border-radius: 20px;
    padding: 2px 8px;
  }
  .card-body { padding: 14px 16px; }
  .card-body label {
    display: block;
    font-size: 0.75rem;
    color: var(--muted);
    margin-bottom: 5px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }
  .card-body textarea, .card-body input[type=text] {
    width: 100%;
    background: #0d0e14;
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.82rem;
    padding: 8px 10px;
    resize: vertical;
    outline: none;
    margin-bottom: 10px;
  }
  .card-body textarea:focus, .card-body input:focus { border-color: var(--accent2); }
  .fire-btn {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 5px;
    padding: 7px 18px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.15s;
  }
  .fire-btn:hover { opacity: 0.85; }
  .fire-btn:active { opacity: 0.7; }

  /* Response panel */
  aside {
    background: var(--surface);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .aside-header {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--muted);
    letter-spacing: 1px;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  #status-pill {
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 20px;
    font-weight: 700;
    display: none;
  }
  .status-2xx { background: #14301e; color: var(--green); display: inline !important; }
  .status-4xx { background: #2a1a10; color: var(--yellow); display: inline !important; }
  .status-5xx { background: #2a1010; color: var(--red); display: inline !important; }
  #response-meta {
    padding: 8px 16px;
    font-size: 0.75rem;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    min-height: 28px;
  }
  #response-body {
    flex: 1;
    overflow-y: auto;
    padding: 14px 16px;
    font-family: var(--mono);
    font-size: 0.78rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--text);
  }
  .response-headers {
    padding: 8px 16px;
    font-size: 0.72rem;
    font-family: var(--mono);
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: pre;
    overflow-x: auto;
    max-height: 120px;
    overflow-y: auto;
  }
</style>
</head>
<body>

<header>
  <div class="logo">⚡ ICARUS</div>
  <div class="sub">Deliberately Vulnerable Lab</div>
  <div class="badge">⚠ TESTING ONLY</div>
</header>

<div class="layout">
  <nav>
    <div class="section-label">Modules</div>
    <a href="#" class="active" onclick="show(event, 'jwt')">
      <span class="dot" style="background:#F78C6C"></span>JWT Checker
    </a>
    <a href="#" onclick="show(event, 'param')">
      <span class="dot" style="background:#82AAFF"></span>ParamValidator
    </a>
    <a href="#" onclick="show(event, 'verb')">
      <span class="dot" style="background:#FFCB6B"></span>HTTP Verb Tester
    </a>
    <a href="#" onclick="show(event, 'rate')">
      <span class="dot" style="background:#C3E88D"></span>Rate Limit
    </a>
    <a href="#" onclick="show(event, 'headers')">
      <span class="dot" style="background:#FF5370"></span>Sensitive Headers
    </a>
    <a href="#" onclick="show(event, 'error')">
      <span class="dot" style="background:#89DDFF"></span>Passive Error
    </a>
    <a href="#" onclick="show(event, 'auth')">
      <span class="dot" style="background:#C792EA"></span>AutoAuth
    </a>
  </nav>

  <main>

    <!-- JWT Checker -->
    <div class="module active" id="mod-jwt">
      <div class="module-title">JWT Checker</div>
      <div class="module-desc">Targets: weak HS256 secret, alg=none, missing claims, privilege escalation, kid path traversal</div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/auth/login</span>
          <span class="vuln-tag">WEAK_MAC · MISSING_CLAIMS</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="jwt-login-body" rows="3">{"username": "alice", "password": "alice123"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/auth/login','jwt-login-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/auth/login-none</span>
          <span class="vuln-tag">ALG_NONE · CRITICAL</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="jwt-none-body" rows="2">{"username": "alice"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/auth/login-none','jwt-none-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/auth/login-nonclaims</span>
          <span class="vuln-tag">MISSING_EXP · MISSING_IAT · ...</span>
        </div>
        <div class="card-body">
          <button class="fire-btn" onclick="fire('POST','/api/auth/login-nonclaims',null)">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method GET">GET</span>
          <span class="endpoint-path">/api/protected/admin</span>
          <span class="vuln-tag">PRIV ESC — role check on unverified payload</span>
        </div>
        <div class="card-body">
          <label>Authorization Header</label>
          <input type="text" id="jwt-admin-token" placeholder="Bearer eyJ...">
          <button class="fire-btn" onclick="fireWithAuth('GET','/api/protected/admin','jwt-admin-token')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method GET">GET</span>
          <span class="endpoint-path">/api/protected/profile</span>
          <span class="vuln-tag">Protected endpoint</span>
        </div>
        <div class="card-body">
          <label>Authorization Header</label>
          <input type="text" id="jwt-profile-token" placeholder="Bearer eyJ...">
          <button class="fire-btn" onclick="fireWithAuth('GET','/api/protected/profile','jwt-profile-token')">Send →</button>
        </div>
      </div>
    </div>

    <!-- ParamValidator -->
    <div class="module" id="mod-param">
      <div class="module-title">ParamValidator</div>
      <div class="module-desc">Targets: no type/structural/boundary validation, XSS reflection, raw SQLi string concatenation</div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/items</span>
          <span class="vuln-tag">No validation — structural · type · boundary</span>
        </div>
        <div class="card-body">
          <label>Body (mutate me)</label>
          <textarea id="param-items-body" rows="6">{"name": "widget", "price": 9.99, "quantity": 10, "active": true}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/items','param-items-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/search</span>
          <span class="vuln-tag">XSS Reflection</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="param-search-body" rows="2">{"query": "<script>alert(1)</script>"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/search','param-search-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/sqli</span>
          <span class="vuln-tag">Raw SQL concatenation</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="param-sqli-body" rows="2">{"name": "alice"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/sqli','param-sqli-body')">Send →</button>
        </div>
      </div>
    </div>

    <!-- HTTP Verb Tester -->
    <div class="module" id="mod-verb">
      <div class="module-title">HTTP Verb Tester</div>
      <div class="module-desc">Targets: accepts all verbs, TRACE reflection, Allow header mismatch</div>

      <div class="card">
        <div class="card-header">
          <span class="method ALL">*</span>
          <span class="endpoint-path">/api/resource</span>
          <span class="vuln-tag">Accepts all verbs · TRACE reflects</span>
        </div>
        <div class="card-body">
          <label>Method</label>
          <select id="verb-method" style="background:#0d0e14;border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:5px;margin-bottom:10px;width:100%">
            <option>GET</option><option>POST</option><option>PUT</option>
            <option>DELETE</option><option>PATCH</option><option>OPTIONS</option><option>TRACE</option>
          </select>
          <button class="fire-btn" onclick="fireVerb('/api/resource','verb-method')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method GET">GET</span>
          <span class="endpoint-path">/api/strict</span>
          <span class="vuln-tag">Correctly restricted — baseline</span>
        </div>
        <div class="card-body">
          <button class="fire-btn" onclick="fire('GET','/api/strict',null)">Send →</button>
        </div>
      </div>
    </div>

    <!-- Rate Limit -->
    <div class="module" id="mod-rate">
      <div class="module-title">Rate Limit Tester</div>
      <div class="module-desc">Targets: no lockout on login/OTP (brute-force surface), control endpoint with proper 429</div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/login-rate</span>
          <span class="vuln-tag">No rate limiting</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="rate-login-body" rows="2">{"username": "admin", "password": "wrong"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/login-rate','rate-login-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/otp</span>
          <span class="vuln-tag">No lockout — fixed OTP is 123456</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="rate-otp-body" rows="2">{"otp": "000000"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/otp','rate-otp-body')">Send →</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="method POST">POST</span>
          <span class="endpoint-path">/api/limited-login</span>
          <span class="vuln-tag">429 after 10 requests — control</span>
        </div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="rate-limited-body" rows="2">{"username": "test"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/limited-login','rate-limited-body')">Send →</button>
        </div>
      </div>
    </div>

    <!-- Sensitive Headers -->
    <div class="module" id="mod-headers">
      <div class="module-title">Sensitive Headers</div>
      <div class="module-desc">Targets: version disclosure, debug headers, missing security headers, cookie flags, internal IP leak</div>

      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/headers/bad</span><span class="vuln-tag">X-Powered-By · Debug headers · Server version</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/headers/bad',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/headers/cookie</span><span class="vuln-tag">Missing Secure · HttpOnly · SameSite</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/headers/cookie',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/headers/internal-ip</span><span class="vuln-tag">Internal IP 10.0.0.42 in header</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/headers/internal-ip',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/headers/missing-security</span><span class="vuln-tag">All security headers absent</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/headers/missing-security',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/headers/hsts</span><span class="vuln-tag">Correct headers — baseline</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/headers/hsts',null)">Send →</button></div>
      </div>
    </div>

    <!-- Passive Error -->
    <div class="module" id="mod-error">
      <div class="module-title">Passive Error</div>
      <div class="module-desc">Targets: Python stack traces, SQL errors, PHP warnings, Django verbose debug pages in response body</div>

      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/error/stack</span><span class="vuln-tag">Python Traceback</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/error/stack',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/error/sql</span><span class="vuln-tag">Raw SQL error</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/error/sql',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/error/php</span><span class="vuln-tag">PHP Warning</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/error/php',null)">Send →</button></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/error/verbose</span><span class="vuln-tag">Django debug page</span></div>
        <div class="card-body"><button class="fire-btn" onclick="fire('GET','/api/error/verbose',null)">Send →</button></div>
      </div>
    </div>

    <!-- AutoAuth -->
    <div class="module" id="mod-auth">
      <div class="module-title">AutoAuth</div>
      <div class="module-desc">Targets: token issuance for AutoAuth config, refresh flow, 401 trigger for re-injection</div>

      <div class="card">
        <div class="card-header"><span class="method POST">POST</span><span class="endpoint-path">/api/auth/login</span><span class="vuln-tag">Configure as AutoAuth token endpoint</span></div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="auth-login-body" rows="2">{"username": "alice", "password": "alice123"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/auth/login','auth-login-body')">Send →</button>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method POST">POST</span><span class="endpoint-path">/api/auth/refresh</span><span class="vuln-tag">Refresh token flow</span></div>
        <div class="card-body">
          <label>Body</label>
          <textarea id="auth-refresh-body" rows="2">{"refresh_token": "dummy-token"}</textarea>
          <button class="fire-btn" onclick="fire('POST','/api/auth/refresh','auth-refresh-body')">Send →</button>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="method GET">GET</span><span class="endpoint-path">/api/me</span><span class="vuln-tag">401 without token — AutoAuth re-inject target</span></div>
        <div class="card-body">
          <label>Authorization (leave blank to trigger 401)</label>
          <input type="text" id="auth-me-token" placeholder="Bearer eyJ... (optional)">
          <button class="fire-btn" onclick="fireWithAuth('GET','/api/me','auth-me-token')">Send →</button>
        </div>
      </div>
    </div>

  </main>

  <aside>
    <div class="aside-header">
      RESPONSE
      <span id="status-pill"></span>
    </div>
    <div id="response-meta"></div>
    <div class="response-headers" id="response-headers"></div>
    <div id="response-body">Hit Send on any request to see the response here.</div>
  </aside>
</div>

<script>
const modules = {jwt:'mod-jwt',param:'mod-param',verb:'mod-verb',rate:'mod-rate',headers:'mod-headers',error:'mod-error',auth:'mod-auth'};

function show(e, key) {
  document.querySelectorAll('.module').forEach(m => m.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  document.getElementById(modules[key]).classList.add('active');
  if (e && e.currentTarget) e.currentTarget.classList.add('active');
  return false;
}

async function fire(method, path, bodyId) {
  const body = bodyId ? document.getElementById(bodyId).value : null;
  const headers = {'Content-Type': 'application/json'};
  await doFetch(method, path, headers, body);
}

async function fireWithAuth(method, path, tokenId) {
  const token = document.getElementById(tokenId).value.trim();
  const headers = {'Content-Type': 'application/json'};
  if (token) headers['Authorization'] = token.startsWith('Bearer') ? token : 'Bearer ' + token;
  await doFetch(method, path, headers, null);
}

async function fireVerb(path, selectId) {
  const method = document.getElementById(selectId).value;
  await doFetch(method, path, {}, null);
}

async function doFetch(method, path, headers, body) {
  const pill = document.getElementById('status-pill');
  const meta = document.getElementById('response-meta');
  const hdrs = document.getElementById('response-headers');
  const out  = document.getElementById('response-body');

  pill.className = ''; pill.textContent = ''; pill.style.display = 'none';
  meta.textContent = 'Sending...';
  hdrs.textContent = '';
  out.textContent  = '';

  const t0 = Date.now();
  try {
    const opts = {method, headers};
    if (body && method !== 'GET' && method !== 'HEAD') opts.body = body;
    const res = await fetch(path, opts);
    const ms  = Date.now() - t0;
    const text = await res.text();

    pill.textContent = res.status;
    pill.style.display = 'inline';
    if (res.status < 300)      pill.className = 'status-2xx';
    else if (res.status < 500) pill.className = 'status-4xx';
    else                       pill.className = 'status-5xx';

    meta.textContent = method + ' ' + path + '  —  ' + ms + 'ms  |  ' + text.length + ' bytes';

    let hdrLines = '';
    res.headers.forEach((v,k) => { hdrLines += k + ': ' + v + '\n'; });
    hdrs.textContent = hdrLines;

    try { out.textContent = JSON.stringify(JSON.parse(text), null, 2); }
    catch (e) { out.textContent = text; }
  } catch(e) {
    meta.textContent = 'Request failed: ' + e.message;
    out.textContent  = String(e);
  }
}
</script>
</body>
</html>
"""

from flask import make_response

@app.route("/")
def index():
    resp = make_response(render_template_string(UI_HTML))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


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
