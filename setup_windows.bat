@echo off
:: ============================================================
:: setup_windows.bat  Windows environment setup for Pentest LLM
:: ============================================================
:: Requirements: Python 3.10+  https://python.org
:: Double-click to run. Creates .venv in the project folder.
:: ============================================================

setlocal EnableDelayedExpansion
cd /d "%~dp0"

title Pentest LLM - Setup

echo.
echo ============================================
echo   Pentest LLM - Windows Setup
echo ============================================
echo.

:: -- Python version check ------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo         Install Python 3.10+ from https://python.org
    echo         Make sure to check "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [+] Python: %PYVER%

:: -- Create virtual environment ------------------------------
if not exist ".venv" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [+] Virtual environment created.
) else (
    echo [+] Virtual environment already exists (.venv).
)

:: -- Activate venv -------------------------------------------
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)
echo [+] Virtual environment activated.

:: -- Upgrade pip ---------------------------------------------
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: -- Install PyTorch (CPU or CUDA) ---------------------------
echo.
echo [*] Checking for CUDA GPU...
python -c "import subprocess; r=subprocess.run(['nvidia-smi'],capture_output=True); exit(0 if r.returncode==0 else 1)" >nul 2>&1
if errorlevel 1 (
    echo [!] No NVIDIA GPU detected - installing CPU-only PyTorch.
    echo     Training will be slow on CPU. Consider WSL2 + Docker.
    pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet
) else (
    echo [+] NVIDIA GPU detected.
    echo [*] Installing PyTorch with CUDA 12.1 support...
    pip install torch --index-url https://download.pytorch.org/whl/cu121 --quiet
)

:: -- Core training stack -------------------------------------
echo.
echo [*] Installing core training stack (transformers, trl, peft)...
pip install ^
    "transformers>=4.44.0" ^
    "datasets>=2.20.0" ^
    "peft>=0.12.0" ^
    "trl>=0.10.0" ^
    "accelerate>=0.33.0" ^
    --quiet

:: -- bitsandbytes --------------------------------------------
echo [*] Installing bitsandbytes (Windows build)...
pip install bitsandbytes --quiet
if errorlevel 1 (
    echo [!] bitsandbytes failed - trying bitsandbytes-windows prebuilt...
    pip install bitsandbytes-windows --quiet
    if errorlevel 1 (
        echo [!] bitsandbytes not available. Training will use fp32 (slow).
        echo     Consider WSL2 or Docker for full 4-bit QLoRA support.
    )
)

:: -- Utilities -----------------------------------------------
echo [*] Installing utility packages...
pip install ^
    "pyyaml>=6.0" ^
    "numpy>=1.26.0" ^
    "tqdm>=4.66.0" ^
    "requests>=2.32.0" ^
    "scipy>=1.13.0" ^
    "scikit-learn>=1.5.0" ^
    --quiet

:: -- Optional: tensorboard -----------------------------------
pip install tensorboard --quiet

:: -- Verify key imports --------------------------------------
echo.
echo [*] Verifying installation...
python -c "import torch; print('    torch        : ' + torch.__version__ + ' (CUDA=' + str(torch.cuda.is_available()) + ')')"
python -c "import transformers; print('    transformers : ' + transformers.__version__)"
python -c "import trl; print('    trl          : ' + trl.__version__)"
python -c "import peft; print('    peft         : ' + peft.__version__)"
python -c "import datasets; print('    datasets     : ' + datasets.__version__)"

echo.
echo ============================================
echo   Setup complete!
echo ============================================
echo.
echo   NOTE: Unsloth (Linux/CUDA only) is NOT installed.
echo   The training script uses the HuggingFace stack instead.
echo   For faster training: WSL2 + NVIDIA GPU + Docker
echo.
echo   Next step: double-click run_pipeline.bat
echo.
endlocal
pause
