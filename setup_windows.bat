@echo off
:: ============================================================
:: setup_windows.bat  Windows environment setup for Pentest LLM
:: ============================================================
:: Requirements: Python 3.10+  https://python.org
:: Double-click to run. Creates .venv in the project folder.
:: ============================================================

setlocal
cd /d "%~dp0"

title Pentest LLM - Setup

echo.
echo ============================================
echo   Pentest LLM - Windows Setup
echo ============================================
echo.

:: -- Python check --------------------------------------------
python --version >nul 2>&1
if errorlevel 1 goto :no_python

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [+] Python: %PYVER%
echo.

:: -- Clean broken venv if Scripts\python.exe is missing ------
if not exist ".venv" goto :create_venv
if exist ".venv\Scripts\python.exe" goto :venv_ok
echo [!] Existing .venv is broken. Removing and recreating...
rmdir /s /q .venv

:: -- Create venv ---------------------------------------------
:create_venv
echo [*] Creating virtual environment (.venv)...
python -m venv .venv
if errorlevel 1 goto :venv_error
echo [+] Virtual environment created.
goto :activate

:venv_ok
echo [+] Virtual environment already exists (.venv).

:: -- Activate ------------------------------------------------
:activate
call .venv\Scripts\activate.bat
if errorlevel 1 goto :activate_error
echo [+] Virtual environment activated.
echo.

:: -- Upgrade pip ---------------------------------------------
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: -- Detect GPU ----------------------------------------------
echo.
echo [*] Checking for CUDA GPU...
python -c "import subprocess; r=subprocess.run(['nvidia-smi'],capture_output=True); exit(0 if r.returncode==0 else 1)" >nul 2>&1
if errorlevel 1 goto :cpu_torch
echo [+] NVIDIA GPU detected. Installing PyTorch with CUDA 12.1...
pip install torch --index-url https://download.pytorch.org/whl/cu121 --quiet
goto :core_deps

:cpu_torch
echo [!] No NVIDIA GPU - installing CPU-only PyTorch.
echo     Training will be slow on CPU.
pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet

:: -- Core training stack -------------------------------------
:core_deps
echo.
echo [*] Installing core training stack...
pip install "transformers>=4.44.0" "datasets>=2.20.0" "peft>=0.12.0" "trl>=0.10.0" "accelerate>=0.33.0" --quiet

:: -- bitsandbytes --------------------------------------------
echo [*] Installing bitsandbytes...
pip install bitsandbytes --quiet
if errorlevel 1 (
    pip install bitsandbytes-windows --quiet
)

:: -- Utilities -----------------------------------------------
echo [*] Installing utilities...
pip install "pyyaml>=6.0" "numpy>=1.26.0" "tqdm>=4.66.0" "requests>=2.32.0" "scipy>=1.13.0" "scikit-learn>=1.5.0" --quiet

:: -- Optional tensorboard ------------------------------------
pip install tensorboard --quiet

:: -- Verify -------------------------------------------------
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
echo   Next: double-click run_pipeline.bat
echo ============================================
echo.
pause
exit /b 0

:: -- Error handlers ------------------------------------------
:no_python
echo [ERROR] Python not found.
echo         Install Python 3.10+ from https://python.org
echo         Check "Add Python to PATH" during install.
echo.
pause
exit /b 1

:venv_error
echo [ERROR] Failed to create virtual environment.
echo         Try running as Administrator.
echo.
pause
exit /b 1

:activate_error
echo [ERROR] Failed to activate virtual environment.
echo         Try deleting the .venv folder and running again.
echo.
pause
exit /b 1
