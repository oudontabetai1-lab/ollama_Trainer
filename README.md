# Ollama Fine-tuning Environment — Pentest LLM

> **DISCLAIMER**: This environment is designed exclusively for **authorized** security professionals,
> penetration testers, and security researchers. All generated models and techniques must only be
> used in authorized testing environments with explicit written permission. Unauthorized use of
> these techniques is illegal.

---

## Overview

Fine-tuning pipeline to create a penetration testing specialist LLM running on Ollama.
Covers three core vulnerability classes:

| Category | Techniques |
|----------|-----------|
| **XSS** | Reflected, Stored, DOM-based, Mutation, Blind |
| **SQLi** | Union-based, Error-based, Blind Boolean/Time, OOB, Second-order |
| **OS Injection** | Command injection, Path traversal, Argument injection, Header injection |

## Architecture

```
ollama_Trainer/
├── config/
│   ├── training_config.yaml    # Model & training hyperparameters
│   └── dataset_config.yaml     # Dataset composition settings
├── datasets/
│   ├── synthetic/
│   │   ├── generate_dataset.py # Instruction-following dataset generator
│   │   └── augment_dataset.py  # WAF bypass variants & paraphrasing
│   └── processed/              # Split train/val/test JSONL files
├── training/
│   ├── train.py                # QLoRA fine-tuning with Unsloth/TRL
│   └── export_to_ollama.py     # GGUF conversion + Modelfile creation
├── evaluation/
│   ├── evaluate.py             # Automated benchmark evaluation
│   └── interactive_test.py     # REPL for manual testing
├── scripts/
│   └── pipeline.sh             # End-to-end pipeline runner
├── docker/
│   ├── Dockerfile.trainer      # CUDA-enabled training container
│   └── docker-compose.yml      # Full stack (trainer + Ollama + Jupyter)
├── notebooks/
│   └── 01_data_exploration.ipynb
├── output/                     # Generated artifacts (gitignored)
└── requirements.txt
```

## Quick Start

### Option A: Local (with GPU)

```bash
# 1. Install dependencies
pip install -r requirements.txt
# For Unsloth (faster training):
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"

# 2. Run full pipeline
bash scripts/pipeline.sh

# Or step by step:
python datasets/synthetic/generate_dataset.py --split
python datasets/synthetic/augment_dataset.py
python training/train.py
python training/export_to_ollama.py --register
```

### Option B: Docker (recommended)

```bash
# Build and run trainer
docker-compose -f docker/docker-compose.yml up trainer

# Start Ollama server
docker-compose -f docker/docker-compose.yml up ollama -d

# Open Jupyter for exploration
docker-compose -f docker/docker-compose.yml up notebook
# → http://localhost:8888
```

### Option C: Google Colab / RunPod

1. Upload project to Colab or RunPod
2. Select A100/T4 GPU runtime
3. Run `pip install -r requirements.txt`
4. Run `python training/train.py` — Unsloth auto-detects and optimizes

## Configuration

### Choose Your Base Model (`config/training_config.yaml`)

| Model | VRAM | Quality | Speed |
|-------|------|---------|-------|
| `llama3.2:1b` | ~4 GB | Basic | Very fast |
| `llama3.2:3b` | ~6 GB | Good | Fast |
| `llama3.1:8b` | ~12 GB | Great | Medium |
| `mistral:7b` | ~10 GB | Great | Medium |
| `qwen2.5:7b` | ~10 GB | Excellent | Medium |

### Training Method

```yaml
training:
  method: "lora"     # lora = fast, qlora = memory-efficient
  lora_rank: 16      # Higher = more capacity, more VRAM
  num_epochs: 3      # Increase for better quality
```

## Dataset

The dataset uses **Alpaca instruction-following format**:

```json
{
  "instruction": "How do you detect blind SQL injection?",
  "input": "Target: PostgreSQL login form",
  "output": "## Blind SQL Injection Detection\n...",
  "metadata": {"category": "sqli", "subcategory": "blind_boolean"}
}
```

### Augmentation

The `augment_dataset.py` script adds:
- **WAF bypass variants**: URL-encoded, HTML-encoded, case-variation payloads
- **Instruction paraphrases**: Multiple phrasings of the same question

### Adding Custom Data

Create a JSONL file with the same schema and place it in `datasets/raw/`.
Then run `generate_dataset.py --split` to merge and re-split.

## Export to Ollama

```bash
python training/export_to_ollama.py \
    --adapter-dir ./output/models \
    --model-name pentest-llm \
    --register        # Auto-register with local Ollama
```

This will:
1. Merge LoRA adapters into the base model
2. Convert to GGUF (q4_k_m quantization)
3. Generate a `Modelfile` with the pentest system prompt
4. Register with Ollama (if `--register` is passed)

## Evaluation

```bash
# Automated benchmark
python evaluation/evaluate.py --model-name pentest-llm

# Interactive REPL
python evaluation/interactive_test.py --mode interactive

# Quick category test
python evaluation/interactive_test.py --mode quick --category xss
```

## Pipeline Flags

```bash
bash scripts/pipeline.sh [flags]

Flags:
  --skip-dataset     Skip dataset generation (use existing)
  --skip-train       Skip training (use existing model)
  --skip-export      Skip GGUF export
  --register         Auto-register model with Ollama
  --model-name=NAME  Set output model name (default: pentest-llm)
```

## Requirements

- Python 3.10+
- CUDA 12.1+ (for GPU training)
- 6–12 GB VRAM (depends on model size)
- Ollama (for inference): `curl -fsSL https://ollama.com/install.sh | sh`
- llama.cpp (for GGUF conversion): `git clone https://github.com/ggerganov/llama.cpp`

## Legal Notice

This tool is provided for educational and authorized security testing purposes only.
Users are responsible for ensuring they have explicit authorization before testing
any system. The authors assume no liability for misuse.
