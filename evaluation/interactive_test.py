#!/usr/bin/env python3
"""
Interactive testing interface for the fine-tuned pentest LLM.
Supports single queries and batch testing with color output.
"""

import json
import sys
import argparse
from pathlib import Path

import requests


OLLAMA_URL = "http://localhost:11434"

# ANSI colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


QUICK_TESTS = {
    "xss": [
        "What are the most common XSS injection points in a web application?",
        "How do I test for stored XSS in a comment section?",
        "What is the difference between reflected and DOM-based XSS?",
    ],
    "sqli": [
        "How do I detect SQL injection in a search parameter?",
        "What is the ORDER BY technique for finding column count in SQLi?",
        "Explain time-based blind SQL injection.",
    ],
    "osi": [
        "What characters can be used to inject OS commands?",
        "How do you detect blind OS command injection?",
        "Explain how path traversal can lead to RCE.",
    ],
}


def stream_query(model: str, prompt: str, system: str = "") -> str:
    """Stream a response from Ollama and print in real-time."""
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": True,
        "options": {"temperature": 0.7, "num_ctx": 4096},
    }

    full_response = ""
    print(f"\n{CYAN}{BOLD}[Model: {model}]{RESET}\n")

    with requests.post(
        f"{OLLAMA_URL}/api/generate",
        json=payload,
        stream=True,
        timeout=120,
    ) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if line:
                chunk = json.loads(line)
                token = chunk.get("response", "")
                print(token, end="", flush=True)
                full_response += token
                if chunk.get("done", False):
                    break

    print("\n")
    return full_response


def run_quick_tests(model: str, category: str = "all") -> None:
    """Run a set of quick diagnostic tests."""
    categories = QUICK_TESTS if category == "all" else {category: QUICK_TESTS.get(category, [])}

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD} Quick Test Suite — {model}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    for cat, prompts in categories.items():
        print(f"{YELLOW}{BOLD}[{cat.upper()}]{RESET}")
        for prompt in prompts:
            print(f"\n{GREEN}Q: {prompt}{RESET}")
            stream_query(model, prompt)
            input(f"{CYAN}[Press Enter for next...]{RESET}")


def interactive_mode(model: str) -> None:
    """Run an interactive REPL for querying the model."""
    system = (
        "You are an expert penetration tester. Help security professionals "
        "identify and understand vulnerabilities for authorized testing only."
    )

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD} Pentest LLM Interactive Mode{RESET}")
    print(f"{BOLD} Model: {model}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}Commands: 'quit' to exit, 'clear' to reset context{RESET}\n")

    while True:
        try:
            prompt = input(f"{GREEN}You> {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}Goodbye!{RESET}")
            break

        if not prompt:
            continue
        if prompt.lower() in ("quit", "exit", "q"):
            print(f"{YELLOW}Goodbye!{RESET}")
            break

        stream_query(model, prompt, system=system)


def main():
    parser = argparse.ArgumentParser(description="Interactive pentest LLM tester")
    parser.add_argument("--model", default="pentest-llm", help="Ollama model name")
    parser.add_argument(
        "--mode",
        choices=["interactive", "quick", "single"],
        default="interactive",
        help="Test mode",
    )
    parser.add_argument(
        "--category",
        choices=["xss", "sqli", "osi", "all"],
        default="all",
        help="Category for quick tests",
    )
    parser.add_argument("--prompt", help="Single prompt for 'single' mode")
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama API URL",
    )
    args = parser.parse_args()

    global OLLAMA_URL
    OLLAMA_URL = args.ollama_url

    # Check Ollama
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        models = [m["name"] for m in r.json().get("models", [])]
        if args.model not in models and not any(args.model in m for m in models):
            print(f"{YELLOW}[!] Model '{args.model}' not found. Available: {models}{RESET}")
            print(f"{YELLOW}    Run: ollama pull llama3.2:3b  (or create your fine-tuned model){RESET}")
    except requests.exceptions.ConnectionError:
        print(f"{RED}[-] Cannot connect to Ollama at {OLLAMA_URL}{RESET}")
        print(f"{RED}    Start Ollama with: ollama serve{RESET}")
        sys.exit(1)

    if args.mode == "interactive":
        interactive_mode(args.model)
    elif args.mode == "quick":
        run_quick_tests(args.model, args.category)
    elif args.mode == "single":
        if not args.prompt:
            print(f"{RED}[-] --prompt required for single mode{RESET}")
            sys.exit(1)
        stream_query(args.model, args.prompt)


if __name__ == "__main__":
    main()
