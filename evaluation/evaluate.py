#!/usr/bin/env python3
"""
Evaluation suite for the fine-tuned penetration testing LLM.
Tests model accuracy, coverage, and response quality via Ollama API.
"""

import json
import time
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

import requests

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

OLLAMA_BASE_URL = "http://localhost:11434"


@dataclass
class EvalResult:
    instruction: str
    expected: str
    generated: str
    category: str
    keyword_score: float
    length_score: float
    has_code_block: bool
    response_time: float


# ─────────────────────────────────────────────
# Evaluation Prompts (held-out test cases)
# ─────────────────────────────────────────────
EVAL_PROMPTS = [
    # ── Baseline (original) ──────────────────────────────────────
    {
        "instruction": "What is a reflected XSS attack and how do you test for it?",
        "category": "xss",
        "expected_keywords": ["reflect", "input", "url", "parameter", "script", "payload"],
        "min_length": 100,
    },
    {
        "instruction": "Explain SQL injection and provide a basic detection technique.",
        "category": "sqli",
        "expected_keywords": ["sql", "inject", "query", "database", "union", "error"],
        "min_length": 100,
    },
    {
        "instruction": "What is OS command injection and what characters are used to inject commands?",
        "category": "osi",
        "expected_keywords": ["command", "inject", "shell", ";", "|", "&&"],
        "min_length": 80,
    },
    {
        "instruction": "How do you identify SQL injection in a login form?",
        "category": "sqli",
        "expected_keywords": ["login", "form", "quote", "'", "--", "bypass"],
        "min_length": 80,
    },
    {
        "instruction": "Describe DOM-based XSS and how it differs from reflected XSS.",
        "category": "xss",
        "expected_keywords": ["dom", "client", "sink", "source", "javascript"],
        "min_length": 100,
    },
    {
        "instruction": "What tools are commonly used for SQL injection testing?",
        "category": "sqli",
        "expected_keywords": ["sqlmap", "burp", "tool"],
        "min_length": 50,
    },
    {
        "instruction": "How can path traversal be combined with log poisoning for RCE?",
        "category": "osi",
        "expected_keywords": ["path", "traversal", "log", "rce", "execute", "code"],
        "min_length": 100,
    },
    {
        "instruction": "What is a WAF bypass technique for XSS?",
        "category": "xss",
        "expected_keywords": ["waf", "bypass", "encode", "filter", "evad"],
        "min_length": 60,
    },
    # ── Advanced XSS ─────────────────────────────────────────────
    {
        "instruction": "What is mutation XSS (mXSS) and how does it bypass sanitizers like DOMPurify?",
        "category": "xss",
        "expected_keywords": ["mutate", "innerhtml", "sanitiz", "dompur", "namespace", "svg", "reparse"],
        "min_length": 200,
    },
    {
        "instruction": "How do you bypass a Content-Security-Policy that uses strict-dynamic and nonces?",
        "category": "xss",
        "expected_keywords": ["csp", "nonce", "strict-dynamic", "bypass", "gadget", "jsonp", "allowlist"],
        "min_length": 200,
    },
    {
        "instruction": "Explain how prototype pollution leads to XSS and provide detection methodology.",
        "category": "xss",
        "expected_keywords": ["prototype", "pollution", "__proto__", "gadget", "merge", "lodash", "xss"],
        "min_length": 200,
    },
    {
        "instruction": "What are XS-Leaks and how do they enable cross-origin information disclosure?",
        "category": "xss",
        "expected_keywords": ["xs-leak", "side channel", "timing", "frame", "cache", "cors", "samesite"],
        "min_length": 150,
    },
    # ── Advanced SQLi ─────────────────────────────────────────────
    {
        "instruction": "How do you exploit MongoDB NoSQL injection to bypass authentication?",
        "category": "sqli",
        "expected_keywords": ["mongodb", "nosql", "$gt", "$ne", "operator", "regex", "authentication"],
        "min_length": 150,
    },
    {
        "instruction": "Explain out-of-band SQL injection and how to exfiltrate data via DNS.",
        "category": "sqli",
        "expected_keywords": ["oob", "dns", "xp_dirtree", "utl_http", "exfil", "collaborator", "blind"],
        "min_length": 150,
    },
    {
        "instruction": "Describe second-order SQL injection and give a concrete example of exploitation.",
        "category": "sqli",
        "expected_keywords": ["second-order", "stored", "retrieve", "parameteriz", "register", "phase"],
        "min_length": 150,
    },
    {
        "instruction": "How do you perform GraphQL injection and abuse batching to bypass rate limits?",
        "category": "sqli",
        "expected_keywords": ["graphql", "introspect", "mutation", "batch", "rate limit", "alias"],
        "min_length": 150,
    },
    # ── Injection (SSTI / XXE / SSRF / Deser) ──────────────────
    {
        "instruction": "How do you identify and exploit SSTI in a Jinja2 template for RCE?",
        "category": "injection",
        "expected_keywords": ["ssti", "jinja2", "mro", "subclass", "popen", "rce", "template"],
        "min_length": 200,
    },
    {
        "instruction": "Describe blind XXE out-of-band exfiltration using an external DTD.",
        "category": "injection",
        "expected_keywords": ["xxe", "dtd", "external", "oob", "entity", "exfil", "dns"],
        "min_length": 200,
    },
    {
        "instruction": "How do you exploit SSRF to steal AWS IAM credentials via IMDSv1?",
        "category": "injection",
        "expected_keywords": ["ssrf", "imds", "169.254.169.254", "iam", "credentials", "aws", "role"],
        "min_length": 200,
    },
    {
        "instruction": "Explain Java deserialization attacks and how gadget chains achieve RCE.",
        "category": "injection",
        "expected_keywords": ["deserializ", "gadget", "ysoserial", "commonscollections", "readobject", "rce"],
        "min_length": 200,
    },
    # ── Auth Attacks ───────────────────────────────────────────
    {
        "instruction": "How do you exploit JWT algorithm confusion (RS256 to HS256) for privilege escalation?",
        "category": "auth",
        "expected_keywords": ["jwt", "rs256", "hs256", "public key", "algorithm", "confusion", "forge"],
        "min_length": 200,
    },
    {
        "instruction": "What OAuth 2.0 vulnerabilities lead to account takeover and how do you test them?",
        "category": "auth",
        "expected_keywords": ["oauth", "redirect_uri", "state", "csrf", "code", "interception", "takeover"],
        "min_length": 150,
    },
    {
        "instruction": "How does XML Signature Wrapping (XSW) bypass SAML authentication?",
        "category": "auth",
        "expected_keywords": ["saml", "xsw", "signature", "wrapping", "unsigned", "nameid", "assertion"],
        "min_length": 150,
    },
    # ── Network / Protocol ────────────────────────────────────
    {
        "instruction": "Explain CL.TE HTTP request smuggling and how to exploit it to capture victim requests.",
        "category": "network",
        "expected_keywords": ["smuggling", "cl.te", "content-length", "chunked", "transfer-encoding", "victim", "poison"],
        "min_length": 200,
    },
    {
        "instruction": "How do you exploit race conditions to bypass one-time coupon code limits?",
        "category": "network",
        "expected_keywords": ["race", "condition", "parallel", "simultaneous", "limit", "bypass", "asyncio"],
        "min_length": 150,
    },
    {
        "instruction": "What is Cross-Site WebSocket Hijacking (CSWSH) and how do you exploit it?",
        "category": "network",
        "expected_keywords": ["websocket", "hijack", "origin", "csrf", "cookie", "cswsh", "cross-site"],
        "min_length": 150,
    },
    # ── Attack Chains ──────────────────────────────────────────
    {
        "instruction": "Walk through the complete attack chain from SSRF discovery to AWS EC2 command execution.",
        "category": "attack_chain",
        "expected_keywords": ["ssrf", "imds", "iam", "credentials", "aws", "ssm", "exec", "rce"],
        "min_length": 300,
    },
    {
        "instruction": "Describe how stored XSS can be chained with CSRF token theft for admin account takeover.",
        "category": "attack_chain",
        "expected_keywords": ["stored", "xss", "csrf", "token", "admin", "takeover", "fetch", "same-origin"],
        "min_length": 300,
    },
    {
        "instruction": "How do you pivot from XXE to Kubernetes cluster compromise via the service account token?",
        "category": "attack_chain",
        "expected_keywords": ["xxe", "ssrf", "kubernetes", "service account", "token", "secret", "privileged"],
        "min_length": 300,
    },
]


def call_ollama(
    model_name: str,
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.3,
    timeout: int = 120,
) -> tuple[str, float]:
    """Send a prompt to Ollama and return (response, elapsed_seconds)."""
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": 4096,
        },
    }
    if system:
        payload["system"] = system

    start = time.time()
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json=payload,
        timeout=timeout,
    )
    elapsed = time.time() - start
    resp.raise_for_status()
    return resp.json()["response"], elapsed


def keyword_score(response: str, keywords: list[str]) -> float:
    """Fraction of expected keywords found in response (case-insensitive)."""
    resp_lower = response.lower()
    found = sum(1 for kw in keywords if kw.lower() in resp_lower)
    return found / len(keywords) if keywords else 0.0


def evaluate_model(
    model_name: str,
    test_data_path: Optional[str] = None,
    output_path: str = "./output/evaluation_results.json",
) -> dict:
    """Run full evaluation suite and return metrics."""

    # Check Ollama is running
    try:
        requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5).raise_for_status()
    except requests.exceptions.ConnectionError:
        log.error("[-] Ollama not running. Start with: ollama serve")
        raise

    # Use built-in prompts + optional external test data
    prompts = list(EVAL_PROMPTS)

    if test_data_path and Path(test_data_path).exists():
        with open(test_data_path, encoding="utf-8") as f:
            for line in f:
                item = json.loads(line.strip())
                # Convert training sample to eval format
                prompts.append({
                    "instruction": item.get("instruction", ""),
                    "category": item.get("metadata", {}).get("category", "unknown"),
                    "expected_keywords": [],
                    "min_length": 50,
                    "_expected_output": item.get("output", ""),
                })

    results: list[EvalResult] = []
    category_scores: dict[str, list[float]] = {}

    log.info(f"[*] Evaluating {model_name} on {len(prompts)} prompts...")

    for i, prompt_cfg in enumerate(prompts, 1):
        instruction = prompt_cfg["instruction"]
        category = prompt_cfg.get("category", "unknown")
        expected_kws = prompt_cfg.get("expected_keywords", [])
        min_length = prompt_cfg.get("min_length", 50)

        log.info(f"[{i}/{len(prompts)}] {category}: {instruction[:60]}...")

        try:
            response, elapsed = call_ollama(
                model_name=model_name,
                prompt=instruction,
                temperature=0.3,
            )
        except Exception as e:
            log.error(f"[-] Error: {e}")
            continue

        kw_score = keyword_score(response, expected_kws)
        len_score = min(1.0, len(response) / max(min_length * 2, 1))
        has_code = "```" in response

        result = EvalResult(
            instruction=instruction,
            expected=prompt_cfg.get("_expected_output", ""),
            generated=response,
            category=category,
            keyword_score=kw_score,
            length_score=len_score,
            has_code_block=has_code,
            response_time=elapsed,
        )
        results.append(result)

        if category not in category_scores:
            category_scores[category] = []
        category_scores[category].append(kw_score)

        log.info(
            f"    keyword_score={kw_score:.2f}  "
            f"length_score={len_score:.2f}  "
            f"has_code={has_code}  "
            f"time={elapsed:.1f}s"
        )

    # ─── Aggregate Metrics ────────────────────────────────────
    all_kw = [r.keyword_score for r in results]
    all_len = [r.length_score for r in results]
    all_code = [r.has_code_block for r in results]
    all_time = [r.response_time for r in results]

    metrics = {
        "model": model_name,
        "total_samples": len(results),
        "overall": {
            "avg_keyword_score": sum(all_kw) / len(all_kw) if all_kw else 0,
            "avg_length_score": sum(all_len) / len(all_len) if all_len else 0,
            "code_block_rate": sum(all_code) / len(all_code) if all_code else 0,
            "avg_response_time": sum(all_time) / len(all_time) if all_time else 0,
        },
        "by_category": {
            cat: {"avg_keyword_score": sum(scores) / len(scores)}
            for cat, scores in category_scores.items()
        },
        "samples": [asdict(r) for r in results],
    }

    # ─── Print Summary ────────────────────────────────────────
    print("\n" + "=" * 50)
    print(f" Evaluation Results: {model_name}")
    print("=" * 50)
    print(f"  Samples evaluated  : {metrics['total_samples']}")
    print(f"  Avg keyword score  : {metrics['overall']['avg_keyword_score']:.2%}")
    print(f"  Avg length score   : {metrics['overall']['avg_length_score']:.2%}")
    print(f"  Code block rate    : {metrics['overall']['code_block_rate']:.2%}")
    print(f"  Avg response time  : {metrics['overall']['avg_response_time']:.1f}s")
    print("\n  By category:")
    for cat, cat_metrics in metrics["by_category"].items():
        print(f"    {cat:10s}: {cat_metrics['avg_keyword_score']:.2%}")
    print("=" * 50)

    # Save results
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    log.info(f"[+] Results saved to {output_path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Evaluate pentest LLM via Ollama")
    parser.add_argument("--model-name", default="pentest-llm", help="Ollama model name")
    parser.add_argument(
        "--test-data",
        default=None,
        help="Optional JSONL test dataset",
    )
    parser.add_argument(
        "--output",
        default="./output/evaluation_results.json",
        help="Output path for results JSON",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama API base URL",
    )
    args = parser.parse_args()

    global OLLAMA_BASE_URL
    OLLAMA_BASE_URL = args.ollama_url

    evaluate_model(
        model_name=args.model_name,
        test_data_path=args.test_data,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
