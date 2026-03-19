#!/usr/bin/env python3
"""
Export fine-tuned model to GGUF format and create Ollama Modelfile.
Pipeline: HuggingFace LoRA adapter → merged model → GGUF → Ollama

Requirements:
    pip install llama-cpp-python
    # llama.cpp must be installed for conversion
"""

import os
import subprocess
import argparse
import logging
from pathlib import Path

import yaml

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MODELFILE_TEMPLATE = """FROM {gguf_path}

SYSTEM \"\"\"{system_prompt}\"\"\"

PARAMETER temperature {temperature}
PARAMETER top_p {top_p}
PARAMETER top_k {top_k}
PARAMETER repeat_penalty {repeat_penalty}
PARAMETER num_ctx {context_length}
"""


def merge_lora_weights(adapter_dir: str, output_dir: str) -> str:
    """Merge LoRA adapter weights into the base model."""
    log.info(f"[*] Merging LoRA adapters from {adapter_dir}")

    try:
        from unsloth import FastLanguageModel
        import torch

        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=adapter_dir,
            max_seq_length=4096,
            dtype=None,
            load_in_4bit=True,
        )

        model.save_pretrained_merged(
            output_dir,
            tokenizer,
            save_method="merged_16bit",
        )
        log.info(f"[+] Merged model saved to {output_dir}")
        return output_dir

    except ImportError:
        # Fallback: manual PEFT merge
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
        import torch

        log.info("[*] Using PEFT merge (fallback)")
        base_model_id = _get_base_model_id(adapter_dir)
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_id,
            torch_dtype=torch.float16,
            device_map="cpu",
        )
        tokenizer = AutoTokenizer.from_pretrained(adapter_dir)
        model = PeftModel.from_pretrained(base_model, adapter_dir)
        model = model.merge_and_unload()

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)
        log.info(f"[+] Merged model saved to {output_dir}")
        return output_dir


def _get_base_model_id(adapter_dir: str) -> str:
    """Read base model ID from adapter config."""
    import json

    config_path = Path(adapter_dir) / "adapter_config.json"
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("base_model_name_or_path", "")
    raise ValueError(f"Cannot find adapter_config.json in {adapter_dir}")


def convert_to_gguf(
    model_dir: str,
    output_path: str,
    quantization: str = "q4_k_m",
    llama_cpp_path: str = "/opt/llama.cpp",
) -> str:
    """Convert HuggingFace model to GGUF using llama.cpp."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    convert_script = Path(llama_cpp_path) / "convert_hf_to_gguf.py"
    if not convert_script.exists():
        # Try alternative location
        convert_script = Path(llama_cpp_path) / "convert-hf-to-gguf.py"
    if not convert_script.exists():
        raise FileNotFoundError(
            f"llama.cpp conversion script not found at {llama_cpp_path}\n"
            "Install llama.cpp: git clone https://github.com/ggerganov/llama.cpp"
        )

    # Step 1: Convert to F16 GGUF
    f16_path = str(output).replace(f".{quantization}.gguf", ".f16.gguf")
    log.info(f"[*] Converting to F16 GGUF...")
    subprocess.run(
        [
            "python3",
            str(convert_script),
            model_dir,
            "--outfile",
            f16_path,
            "--outtype",
            "f16",
        ],
        check=True,
    )

    # Step 2: Quantize
    log.info(f"[*] Quantizing to {quantization}...")
    quantize_bin = Path(llama_cpp_path) / "llama-quantize"
    if not quantize_bin.exists():
        quantize_bin = Path(llama_cpp_path) / "quantize"  # older name

    subprocess.run(
        [str(quantize_bin), f16_path, output_path, quantization.upper()],
        check=True,
    )

    # Cleanup F16 file to save space
    Path(f16_path).unlink(missing_ok=True)

    log.info(f"[+] GGUF saved to {output_path}")
    return output_path


def create_modelfile(
    gguf_path: str,
    output_path: str,
    config: dict,
) -> str:
    """Generate an Ollama Modelfile."""
    mf_cfg = config.get("modelfile", {})

    content = MODELFILE_TEMPLATE.format(
        gguf_path=gguf_path,
        system_prompt=mf_cfg.get("system_prompt", "You are a helpful assistant.").strip(),
        temperature=mf_cfg.get("temperature", 0.7),
        top_p=mf_cfg.get("top_p", 0.9),
        top_k=mf_cfg.get("top_k", 40),
        repeat_penalty=mf_cfg.get("repeat_penalty", 1.1),
        context_length=mf_cfg.get("context_length", 4096),
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    log.info(f"[+] Modelfile saved to {output_path}")
    return output_path


def register_with_ollama(modelfile_path: str, model_name: str) -> None:
    """Register the model with local Ollama instance."""
    log.info(f"[*] Registering '{model_name}' with Ollama...")
    result = subprocess.run(
        ["ollama", "create", model_name, "-f", modelfile_path],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        log.info(f"[+] Model '{model_name}' registered successfully!")
        log.info(f"[*] Run it with: ollama run {model_name}")
    else:
        log.error(f"[-] Failed to register model:\n{result.stderr}")
        raise RuntimeError(result.stderr)


def main():
    parser = argparse.ArgumentParser(description="Export fine-tuned model to Ollama")
    parser.add_argument(
        "--adapter-dir",
        default="./output/models",
        help="Directory with LoRA adapter (or merged model)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output/gguf",
        help="Output directory for GGUF files",
    )
    parser.add_argument(
        "--config",
        default="./config/training_config.yaml",
        help="Training config file",
    )
    parser.add_argument(
        "--model-name",
        default="pentest-llm",
        help="Ollama model name",
    )
    parser.add_argument(
        "--llama-cpp",
        default="/opt/llama.cpp",
        help="Path to llama.cpp directory",
    )
    parser.add_argument(
        "--skip-merge",
        action="store_true",
        help="Skip LoRA merge (if model is already merged)",
    )
    parser.add_argument(
        "--skip-convert",
        action="store_true",
        help="Skip GGUF conversion (if GGUF already exists)",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Register model with local Ollama",
    )
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    quantization = config["base_model"]["quantization"]
    model_name = args.model_name

    # Paths
    merged_dir = str(Path(args.output_dir) / "merged")
    gguf_path = str(Path(args.output_dir) / f"{model_name}.{quantization}.gguf")
    modelfile_path = str(Path(args.output_dir) / "Modelfile")

    # Step 1: Merge LoRA
    if not args.skip_merge:
        merge_lora_weights(args.adapter_dir, merged_dir)
    else:
        merged_dir = args.adapter_dir

    # Step 2: Convert to GGUF
    if not args.skip_convert:
        convert_to_gguf(
            model_dir=merged_dir,
            output_path=gguf_path,
            quantization=quantization,
            llama_cpp_path=args.llama_cpp,
        )
    else:
        log.info(f"[*] Skipping conversion, using existing GGUF: {gguf_path}")

    # Step 3: Create Modelfile
    create_modelfile(
        gguf_path=gguf_path,
        output_path=modelfile_path,
        config=config,
    )

    # Step 4: Register (optional)
    if args.register:
        register_with_ollama(modelfile_path, model_name)
    else:
        log.info("\n[*] To register with Ollama, run:")
        log.info(f"    ollama create {model_name} -f {modelfile_path}")
        log.info(f"    ollama run {model_name}")


if __name__ == "__main__":
    main()
