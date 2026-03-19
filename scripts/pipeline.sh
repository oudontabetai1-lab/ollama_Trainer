#!/usr/bin/env bash
# ============================================================
# Full Fine-tuning Pipeline for Pentest LLM
# Usage: ./scripts/pipeline.sh [OPTIONS]
#
# Options:
#   --skip-dataset   Skip dataset generation (use existing)
#   --skip-train     Skip model training
#   --skip-export    Skip GGUF export
#   --register       Register model with Ollama after export
#   --model-name=X   Override output model name (default: pentest-llm)
#   --install-deps   Force reinstall Python dependencies
# ============================================================
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────
CONFIG="./config/training_config.yaml"
DATASET_CONFIG="./config/dataset_config.yaml"
MODEL_NAME="pentest-llm"
LOG_FILE="./output/logs/pipeline_$(date +%Y%m%d_%H%M%S).log"
INSTALL_DEPS=false

# Parse args
SKIP_DATASET=false
SKIP_TRAIN=false
SKIP_EXPORT=false
REGISTER_OLLAMA=false

for arg in "$@"; do
    case $arg in
        --skip-dataset) SKIP_DATASET=true ;;
        --skip-train)   SKIP_TRAIN=true ;;
        --skip-export)  SKIP_EXPORT=true ;;
        --register)     REGISTER_OLLAMA=true ;;
        --model-name=*) MODEL_NAME="${arg#*=}" ;;
        --install-deps) INSTALL_DEPS=true ;;
    esac
done

mkdir -p ./output/logs ./output/models ./output/checkpoints ./output/gguf

tee_log() { tee -a "$LOG_FILE"; }

echo "============================================" | tee_log
echo " Pentest LLM Fine-tuning Pipeline"          | tee_log
echo " $(date)"                                   | tee_log
echo "============================================" | tee_log

# ─── Step 0: Dependency Check & Install ──────────────────────
check_dep() {
    python3 -c "import $1" 2>/dev/null && return 0 || return 1
}

MISSING_DEPS=()
for pkg in trl transformers peft datasets accelerate torch yaml; do
    check_dep "$pkg" || MISSING_DEPS+=("$pkg")
done

if [ ${#MISSING_DEPS[@]} -gt 0 ] || [ "$INSTALL_DEPS" = true ]; then
    echo "" | tee_log
    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo "[!] Missing Python packages: ${MISSING_DEPS[*]}" | tee_log
        echo "[*] Auto-installing required dependencies..." | tee_log
    else
        echo "[*] --install-deps: Reinstalling dependencies..." | tee_log
    fi

    # Install core deps (no unsloth — handled separately for Linux+CUDA)
    pip install \
        "torch>=2.3.0" \
        "transformers>=4.44.0" \
        "datasets>=2.20.0" \
        "peft>=0.12.0" \
        "trl>=0.10.0" \
        "accelerate>=0.33.0" \
        "pyyaml>=6.0" \
        "tqdm>=4.66.0" \
        "requests>=2.32.0" \
        "numpy>=1.26.0" \
        --quiet 2>&1 | tee_log

    # Try bitsandbytes (optional, needed for 4-bit)
    pip install "bitsandbytes>=0.43.0" --quiet 2>&1 || \
        echo "[!] bitsandbytes not installed — fp32 fallback will be used." | tee_log

    # Try unsloth (Linux + CUDA only — will silently fail on Windows)
    pip install unsloth --quiet 2>&1 || \
        echo "[!] Unsloth not installed (Linux+CUDA required) — using HF PEFT fallback." | tee_log

    echo "[+] Dependencies ready." | tee_log
fi

# ─── Step 1: Generate Dataset ────────────────────────────────
if [ "$SKIP_DATASET" = false ]; then
    echo ""
    echo "[STEP 1] Generating dataset..." | tee_log

    python3 datasets/synthetic/generate_dataset.py \
        --format alpaca \
        --output ./datasets/synthetic/pentest_dataset.json \
        --split | tee_log

    echo "[STEP 1] Augmenting dataset..." | tee_log
    python3 datasets/synthetic/augment_dataset.py \
        --input ./datasets/synthetic/pentest_dataset.json \
        --output ./datasets/processed/pentest_augmented.json | tee_log

    # Re-split augmented dataset
    python3 -c "
import json, random, pathlib

with open('./datasets/processed/pentest_augmented.json') as f:
    data = json.load(f)

random.seed(42)
random.shuffle(data)

n = len(data)
splits = {
    'train': data[:int(n*0.85)],
    'val':   data[int(n*0.85):int(n*0.95)],
    'test':  data[int(n*0.95):]
}
for name, subset in splits.items():
    p = pathlib.Path(f'./datasets/processed/{name}.jsonl')
    with open(p, 'w') as f:
        for item in subset:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(f'  {name}: {len(subset)} samples')
" | tee_log

    echo "[+] Dataset ready." | tee_log
fi

# ─── Step 2: Train ───────────────────────────────────────────
if [ "$SKIP_TRAIN" = false ]; then
    echo ""
    echo "[STEP 2] Starting fine-tuning..." | tee_log

    python3 training/train.py \
        --config "$CONFIG" \
        --train ./datasets/processed/train.jsonl \
        --val   ./datasets/processed/val.jsonl | tee_log

    echo "[+] Training complete." | tee_log
fi

# ─── Step 3: Export to Ollama ────────────────────────────────
if [ "$SKIP_EXPORT" = false ]; then
    echo ""
    echo "[STEP 3] Exporting to GGUF and creating Modelfile..." | tee_log

    REGISTER_FLAG=""
    if [ "$REGISTER_OLLAMA" = true ]; then
        REGISTER_FLAG="--register"
    fi

    python3 training/export_to_ollama.py \
        --adapter-dir ./output/models \
        --output-dir  ./output/gguf \
        --config      "$CONFIG" \
        --model-name  "$MODEL_NAME" \
        $REGISTER_FLAG | tee_log

    echo "[+] Export complete." | tee_log
fi

# ─── Step 4: Evaluate ────────────────────────────────────────
echo ""
echo "[STEP 4] Running evaluation..." | tee_log

python3 evaluation/evaluate.py \
    --model-name "$MODEL_NAME" \
    --test-data  ./datasets/processed/test.jsonl \
    --output     ./output/evaluation_results.json | tee_log

echo ""
echo "============================================" | tee_log
echo " Pipeline complete!"                          | tee_log
echo " Model: $MODEL_NAME"                          | tee_log
echo " Modelfile: ./output/gguf/Modelfile"         | tee_log
echo ""
echo " Next steps:"
if [ "$REGISTER_OLLAMA" = false ]; then
    echo "   ollama create $MODEL_NAME -f ./output/gguf/Modelfile"
fi
echo "   ollama run $MODEL_NAME"
echo "============================================" | tee_log
