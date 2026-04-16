@echo off
:: ============================================================
:: generate_dataset.bat  Dataset Generation
:: ============================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

title Pentest LLM - Dataset Generation

echo.
echo ============================================
echo   Pentest LLM - Dataset Generation
echo ============================================
echo.

:: Check and activate venv
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [+] Virtual environment activated.
) else (
    echo [ERROR] .venv not found. Run setup_windows.bat first.
    echo.
    pause
    exit /b 1
)

mkdir datasets\processed 2>nul
mkdir output\logs        2>nul

echo.
echo [1/3] Generating dataset...
echo ----------------------------------------
python datasets\synthetic\generate_dataset.py ^
    --format alpaca ^
    --output datasets\synthetic\pentest_dataset.json ^
    --split
if errorlevel 1 goto :error

echo.
echo [2/3] Augmenting dataset (encoding variants + paraphrases)...
echo ----------------------------------------
python datasets\synthetic\augment_dataset.py ^
    --input  datasets\synthetic\pentest_dataset.json ^
    --output datasets\processed\pentest_augmented.json
if errorlevel 1 goto :error

echo.
echo [3/3] Splitting into train / val / test...
echo ----------------------------------------
python -c "import json,random,pathlib;data=json.load(open('datasets/processed/pentest_augmented.json',encoding='utf-8'));random.seed(42);random.shuffle(data);n=len(data);splits={'train':data[:int(n*0.85)],'val':data[int(n*0.85):int(n*0.95)],'test':data[int(n*0.95):]};[open('datasets/processed/'+k+'.jsonl','w',encoding='utf-8').writelines(json.dumps(v,ensure_ascii=False)+'\n' for v in vs) or print('  '+k+': '+str(len(vs))+' samples') for k,vs in splits.items()]"
if errorlevel 1 goto :error

echo.
echo ============================================
echo   Done!
echo   datasets\synthetic\pentest_dataset.json
echo   datasets\processed\pentest_augmented.json
echo   datasets\processed\train.jsonl
echo   datasets\processed\val.jsonl
echo   datasets\processed\test.jsonl
echo ============================================
echo.
pause
exit /b 0

:error
echo.
echo ============================================
echo   [ERROR] Something went wrong.
echo   Check the error message above.
echo ============================================
echo.
pause
exit /b 1
