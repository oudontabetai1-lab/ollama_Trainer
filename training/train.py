#!/usr/bin/env python3
"""
Fine-tuning pipeline for penetration testing LLM using Unsloth/TRL.
Supports LoRA/QLoRA fine-tuning of models compatible with Ollama.

Requirements:
    pip install unsloth trl transformers datasets peft bitsandbytes
    # GPU: pip install torch --index-url https://download.pytorch.org/whl/cu121
"""

import os
import json
import argparse
import logging
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_dataset(data_path: str, format: str = "alpaca"):
    """Load JSONL or JSON dataset and convert to HuggingFace Dataset."""
    from datasets import Dataset

    path = Path(data_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    records = []
    if path.suffix == ".jsonl":
        with open(path) as f:
            for line in f:
                records.append(json.loads(line.strip()))
    else:
        with open(path) as f:
            records = json.load(f)

    log.info(f"Loaded {len(records)} records from {data_path}")
    return Dataset.from_list(records)


def format_alpaca_prompt(sample: dict, tokenizer) -> str:
    """Format a sample using Alpaca prompt template."""
    alpaca_prompt = """Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Instruction:
{}

### Input:
{}

### Response:
{}"""

    instruction = sample.get("instruction", "")
    inp = sample.get("input", "")
    output = sample.get("output", "")
    eos = tokenizer.eos_token

    return alpaca_prompt.format(instruction, inp, output) + eos


def format_chatml_prompt(sample: dict) -> list[dict]:
    """Return messages list from ChatML format sample."""
    return sample.get("messages", [])


def prepare_model_and_tokenizer(config: dict):
    """Load model with Unsloth for 4-bit QLoRA training."""
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        raise ImportError(
            "Unsloth not installed. Run: pip install unsloth\n"
            "Or use the Docker environment: docker-compose up trainer"
        )

    model_name = f"{config['base_model']['name']}:{config['base_model']['size']}"
    # Map to HuggingFace model ID
    hf_model_map = {
        "llama3.2:3b": "unsloth/Llama-3.2-3B-Instruct-bnb-4bit",
        "llama3.2:1b": "unsloth/Llama-3.2-1B-Instruct-bnb-4bit",
        "llama3.1:8b": "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
        "llama3.1:70b": "unsloth/Meta-Llama-3.1-70B-Instruct-bnb-4bit",
        "mistral:7b": "unsloth/mistral-7b-instruct-v0.3-bnb-4bit",
        "qwen2.5:7b": "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
        "gemma2:9b": "unsloth/gemma-2-9b-it-bnb-4bit",
    }

    hf_model_id = hf_model_map.get(model_name, f"unsloth/{config['base_model']['name']}-bnb-4bit")
    log.info(f"Loading model: {hf_model_id}")

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=hf_model_id,
        max_seq_length=config["training"]["max_seq_length"],
        dtype=None,
        load_in_4bit=True,
    )

    # Apply LoRA adapters
    lora_cfg = config["training"]
    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_cfg["lora_rank"],
        target_modules=lora_cfg["target_modules"],
        lora_alpha=lora_cfg["lora_alpha"],
        lora_dropout=lora_cfg["lora_dropout"],
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    return model, tokenizer


def train(config: dict, train_data_path: str, val_data_path: str | None = None):
    """Run the training loop."""
    from trl import SFTTrainer
    from transformers import TrainingArguments

    model, tokenizer = prepare_model_and_tokenizer(config)

    # Load datasets
    train_dataset = load_dataset(train_data_path)
    val_dataset = load_dataset(val_data_path) if val_data_path else None

    # Format training data
    dataset_format = config.get("dataset", {}).get("format", "alpaca")

    if dataset_format == "alpaca":
        def formatting_func(samples):
            texts = []
            for i in range(len(samples["instruction"])):
                sample = {
                    "instruction": samples["instruction"][i],
                    "input": samples.get("input", [""] * len(samples["instruction"]))[i],
                    "output": samples["output"][i],
                }
                texts.append(format_alpaca_prompt(sample, tokenizer))
            return {"text": texts}

        train_dataset = train_dataset.map(formatting_func, batched=True)
        column_name = "text"
    else:
        column_name = "messages"

    # Training arguments
    t = config["training"]
    output_cfg = config["output"]
    Path(output_cfg["checkpoint_dir"]).mkdir(parents=True, exist_ok=True)
    Path(output_cfg["log_dir"]).mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=output_cfg["checkpoint_dir"],
        num_train_epochs=t["num_epochs"],
        per_device_train_batch_size=t["batch_size"],
        gradient_accumulation_steps=t["gradient_accumulation_steps"],
        learning_rate=t["learning_rate"],
        warmup_ratio=t["warmup_ratio"],
        lr_scheduler_type=t["lr_scheduler"],
        weight_decay=t["weight_decay"],
        fp16=t["fp16"],
        logging_steps=output_cfg["logging_steps"],
        save_steps=output_cfg["save_steps"],
        eval_steps=output_cfg["eval_steps"] if val_dataset else None,
        evaluation_strategy="steps" if val_dataset else "no",
        save_strategy="steps",
        load_best_model_at_end=True if val_dataset else False,
        report_to=["tensorboard"],
        logging_dir=output_cfg["log_dir"],
        dataloader_num_workers=t["dataloader_num_workers"],
        seed=42,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        dataset_text_field=column_name,
        max_seq_length=t["max_seq_length"],
        args=training_args,
    )

    log.info("[*] Starting training...")
    trainer.train()

    # Save final model
    model_dir = Path(output_cfg["model_dir"])
    model_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)
    log.info(f"[+] Model saved to {model_dir}")

    return model, tokenizer


def main():
    parser = argparse.ArgumentParser(description="Fine-tune LLM for penetration testing")
    parser.add_argument(
        "--config",
        default="./config/training_config.yaml",
        help="Training configuration file",
    )
    parser.add_argument(
        "--train",
        default="./datasets/processed/train.jsonl",
        help="Training dataset path",
    )
    parser.add_argument(
        "--val",
        default="./datasets/processed/val.jsonl",
        help="Validation dataset path",
    )
    parser.add_argument(
        "--resume",
        default=None,
        help="Resume from checkpoint directory",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    log.info(f"[*] Loaded config: {args.config}")
    log.info(f"[*] Base model: {config['base_model']['name']}:{config['base_model']['size']}")

    train(
        config=config,
        train_data_path=args.train,
        val_data_path=args.val if Path(args.val).exists() else None,
    )


if __name__ == "__main__":
    main()
