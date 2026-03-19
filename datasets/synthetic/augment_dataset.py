#!/usr/bin/env python3
"""
Dataset augmentation for pentest LLM training data.
Adds encoding variants, evasion techniques, and paraphrasing.
"""

import json
import re
import argparse
from pathlib import Path
from urllib.parse import quote, quote_plus


def url_encode_payload(payload: str, double: bool = False) -> str:
    """URL-encode a payload."""
    encoded = quote(payload, safe="")
    return quote(encoded, safe="") if double else encoded


def html_encode_payload(payload: str) -> str:
    """HTML-entity encode a payload."""
    result = ""
    for ch in payload:
        result += f"&#{ord(ch)};"
    return result


def unicode_encode_payload(payload: str) -> str:
    """Unicode-escape a payload (JS-style)."""
    result = ""
    for ch in payload:
        result += f"\\u{ord(ch):04x}"
    return result


def generate_xss_evasion_variants(payload: str) -> list[str]:
    """Generate WAF-evasion variants of an XSS payload."""
    variants = [payload]

    # Case variation
    variants.append(payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))

    # URL encoding
    variants.append(url_encode_payload(payload))
    variants.append(url_encode_payload(payload, double=True))

    # HTML entities
    variants.append(html_encode_payload(payload))

    # Null bytes between tags (some parsers)
    variants.append(payload.replace("<script>", "<scr\x00ipt>"))

    # Whitespace injection
    variants.append(payload.replace("alert(", "alert\t(").replace("alert(", "alert\n("))

    return list(dict.fromkeys(variants))  # deduplicate preserving order


def generate_sqli_evasion_variants(payload: str) -> list[str]:
    """Generate WAF-evasion variants of a SQL injection payload."""
    variants = [payload]

    # Comment injection
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" UNION ", " UNION/**/ ").replace(" SELECT ", " SELECT/**/ "))

    # Case variation
    variants.append(
        payload.replace("UNION", "uNiOn")
              .replace("SELECT", "SeLeCt")
              .replace("FROM", "fRoM")
    )

    # URL encoding
    variants.append(url_encode_payload(payload))

    # Hex encoding for strings
    def to_hex_string(s: str) -> str:
        return "0x" + s.encode().hex()

    # Replace simple string literals with hex
    def replace_strings_with_hex(p: str) -> str:
        return re.sub(r"'([^']+)'", lambda m: to_hex_string(m.group(1)), p)

    hex_variant = replace_strings_with_hex(payload)
    if hex_variant != payload:
        variants.append(hex_variant)

    return list(dict.fromkeys(variants))


INSTRUCTION_PARAPHRASES = {
    "explain": [
        "Describe",
        "Detail",
        "Walk me through",
        "Break down",
        "Give an overview of",
    ],
    "how do you": [
        "What is the process to",
        "What steps are needed to",
        "How would a tester",
        "Describe the methodology to",
    ],
    "demonstrate": [
        "Show an example of",
        "Provide a walkthrough of",
        "Illustrate",
        "Give a practical example of",
    ],
    "describe": [
        "Explain",
        "Detail",
        "Walk through",
        "Give an in-depth overview of",
    ],
    "walk through": [
        "Explain step by step",
        "Detail the process of",
        "Describe the methodology for",
    ],
    "what are": [
        "Can you explain",
        "Describe",
        "Provide an overview of",
    ],
}


def paraphrase_instruction(instruction: str) -> list[str]:
    """Generate simple paraphrases of an instruction."""
    variants = [instruction]
    lower = instruction.lower()

    for key, replacements in INSTRUCTION_PARAPHRASES.items():
        if key in lower:
            for rep in replacements[:2]:  # Limit to 2 paraphrases each
                variant = re.sub(
                    re.escape(key), rep, instruction, count=1, flags=re.IGNORECASE
                )
                variants.append(variant)
            break

    return variants


def augment_dataset(
    input_path: str,
    output_path: str,
    add_evasion: bool = True,
    add_paraphrases: bool = True,
) -> list[dict]:
    """Load a dataset, augment it, and save the result."""
    with open(input_path, encoding="utf-8") as f:
        dataset = json.load(f)

    augmented = []

    for item in dataset:
        augmented.append(item)
        category = item.get("metadata", {}).get("category", "")

        if add_paraphrases:
            instruction = item.get("instruction", "")
            for para in paraphrase_instruction(instruction)[1:]:  # skip original
                new_item = item.copy()
                new_item["instruction"] = para
                new_item["metadata"] = {**item.get("metadata", {}), "augmented": "paraphrase"}
                augmented.append(new_item)

        if add_evasion:
            output_text = item.get("output", "")

            if category == "xss":
                code_blocks = re.findall(r"```(?:\w+)?\n(.+?)```", output_text, re.DOTALL)
                for block in code_blocks[:1]:  # Augment first code block
                    payloads = [
                        line.strip()
                        for line in block.splitlines()
                        if "<script>" in line or "onerror" in line
                    ]
                    if payloads:
                        variants_note = "\n### Encoding Variants (WAF Bypass)\n```\n"
                        for p in payloads[:2]:
                            for v in generate_xss_evasion_variants(p)[1:3]:
                                variants_note += f"{v}\n"
                        variants_note += "```\n"
                        new_item = item.copy()
                        new_item["output"] = output_text + variants_note
                        new_item["metadata"] = {**item.get("metadata", {}), "augmented": "evasion"}
                        augmented.append(new_item)

            elif category == "sqli":
                code_blocks = re.findall(r"```(?:sql|bash)?\n(.+?)```", output_text, re.DOTALL)
                for block in code_blocks[:1]:
                    payloads = [
                        line.strip()
                        for line in block.splitlines()
                        if any(kw in line.upper() for kw in ("UNION", "SELECT", "SLEEP", "WAITFOR"))
                    ]
                    if payloads:
                        variants_note = "\n### WAF Evasion Variants\n```sql\n"
                        for p in payloads[:2]:
                            for v in generate_sqli_evasion_variants(p)[1:3]:
                                variants_note += f"{v}\n"
                        variants_note += "```\n"
                        new_item = item.copy()
                        new_item["output"] = output_text + variants_note
                        new_item["metadata"] = {**item.get("metadata", {}), "augmented": "evasion"}
                        augmented.append(new_item)

            elif category == "injection":
                subcategory = item.get("metadata", {}).get("subcategory", "")
                if subcategory == "ssti":
                    # Add platform variants note
                    variants_note = (
                        "\n### Quick Engine Detection Reference\n"
                        "| Payload | Result | Engine |\n"
                        "|---------|--------|--------|\n"
                        "| `{{7*7}}` | `49` | Jinja2, Twig |\n"
                        "| `${7*7}` | `49` | FreeMarker, Thymeleaf |\n"
                        "| `<%= 7*7 %>` | `49` | ERB (Ruby) |\n"
                        "| `#{7*7}` | `49` | Ruby Slim |\n"
                        "| `{{7*'7'}}` | `7777777` | Jinja2 |\n"
                        "| `{{7*'7'}}` | `49` | Twig |\n"
                    )
                    new_item = item.copy()
                    new_item["output"] = output_text + variants_note
                    new_item["metadata"] = {**item.get("metadata", {}), "augmented": "ssti_reference"}
                    augmented.append(new_item)

    print(f"[+] Original: {len(dataset)} → Augmented: {len(augmented)} samples")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(augmented, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved to {output_path}")

    return augmented


def main():
    parser = argparse.ArgumentParser(description="Augment pentest training dataset")
    parser.add_argument(
        "--input",
        default="./datasets/synthetic/pentest_dataset.json",
        help="Input dataset path",
    )
    parser.add_argument(
        "--output",
        default="./datasets/processed/pentest_augmented.json",
        help="Output dataset path",
    )
    parser.add_argument("--no-evasion", action="store_true", help="Skip evasion variants")
    parser.add_argument(
        "--no-paraphrase", action="store_true", help="Skip paraphrases"
    )
    args = parser.parse_args()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    augment_dataset(
        input_path=args.input,
        output_path=args.output,
        add_evasion=not args.no_evasion,
        add_paraphrases=not args.no_paraphrase,
    )


if __name__ == "__main__":
    main()
