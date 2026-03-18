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
        with open(test_data_path) as f:
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
    with open(output_path, "w") as f:
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
