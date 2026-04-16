@echo off
:: ============================================================
:: run_pipeline.bat  Fine-tuning Pipeline Launcher
:: ============================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

title Pentest LLM - Pipeline

:menu
cls
echo.
echo ============================================
echo   Pentest LLM  Fine-tuning Pipeline
echo   Base model: qwen2.5-coder:3b
echo ============================================
echo.
echo   1. Run full pipeline  (recommended)
echo      Dataset -^> Train -^> Export -^> Evaluate
echo.
echo   2. Generate dataset only
echo.
echo   3. Train only
echo      (requires dataset)
echo.
echo   4. Export to Ollama only
echo      (requires trained model)
echo.
echo   5. Evaluate only
echo      (requires exported model)
echo.
echo   Q. Quit
echo.
set /p CHOICE="Enter number: "

if /i "%CHOICE%"=="1" goto :pipeline_full
if /i "%CHOICE%"=="2" goto :step_dataset
if /i "%CHOICE%"=="3" goto :step_train
if /i "%CHOICE%"=="4" goto :step_export
if /i "%CHOICE%"=="5" goto :step_eval
if /i "%CHOICE%"=="q" exit /b 0
if /i "%CHOICE%"=="Q" exit /b 0

echo.
echo   [!] Invalid input. Enter 1-5 or Q.
timeout /t 2 >nul
goto :menu

:: -------------------------------------------------------------
:activate_venv
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [+] Virtual environment activated.
    exit /b 0
)
echo [ERROR] .venv not found. Run setup_windows.bat first.
pause
exit /b 1

:: -------------------------------------------------------------
:pipeline_full
cls
echo.
echo ============================================
echo   Running full pipeline
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_dataset
if errorlevel 1 goto :error
call :do_train
if errorlevel 1 goto :error
call :do_export
if errorlevel 1 goto :error
call :do_eval
if errorlevel 1 goto :error
goto :done_full

:step_dataset
cls
echo.
echo ============================================
echo   Dataset generation
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_dataset
if errorlevel 1 goto :error
goto :done

:step_train
cls
echo.
echo ============================================
echo   Training
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_train
if errorlevel 1 goto :error
goto :done

:step_export
cls
echo.
echo ============================================
echo   Export to Ollama
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_export
if errorlevel 1 goto :error
goto :done

:step_eval
cls
echo.
echo ============================================
echo   Evaluation
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_eval
if errorlevel 1 goto :error
goto :done

:: -------------------------------------------------------------
:: Subroutines
:: -------------------------------------------------------------

:do_dataset
echo.
echo [1/3] Generating dataset...
echo ----------------------------------------
mkdir datasets\processed 2>nul
mkdir output\logs        2>nul
python datasets\synthetic\generate_dataset.py ^
    --format alpaca ^
    --output datasets\synthetic\pentest_dataset.json ^
    --split
if errorlevel 1 exit /b 1
echo.
echo [2/3] Augmenting dataset...
echo ----------------------------------------
python datasets\synthetic\augment_dataset.py ^
    --input  datasets\synthetic\pentest_dataset.json ^
    --output datasets\processed\pentest_augmented.json
if errorlevel 1 exit /b 1
echo.
echo [3/3] Splitting into train/val/test...
python -c "import json,random,pathlib;data=json.load(open('datasets/processed/pentest_augmented.json',encoding='utf-8'));random.seed(42);random.shuffle(data);n=len(data);splits={'train':data[:int(n*0.85)],'val':data[int(n*0.85):int(n*0.95)],'test':data[int(n*0.95):]};[open('datasets/processed/'+k+'.jsonl','w',encoding='utf-8').writelines(json.dumps(v,ensure_ascii=False)+'\n' for v in vs) or print('  '+k+': '+str(len(vs))+' samples') for k,vs in splits.items()]"
if errorlevel 1 exit /b 1
echo [+] Dataset ready.
exit /b 0

:do_train
echo.
echo [TRAIN] Starting fine-tuning...
echo ----------------------------------------
mkdir output\models      2>nul
mkdir output\checkpoints 2>nul
mkdir output\logs        2>nul
python training\train.py ^
    --config config\training_config.yaml ^
    --train  datasets\processed\train.jsonl ^
    --val    datasets\processed\val.jsonl
if errorlevel 1 exit /b 1
echo [+] Training complete.
exit /b 0

:do_export
echo.
echo [EXPORT] Converting to GGUF and generating Modelfile...
echo ----------------------------------------
mkdir output\gguf 2>nul
python training\export_to_ollama.py ^
    --adapter-dir output\models ^
    --output-dir  output\gguf ^
    --config      config\training_config.yaml ^
    --model-name  pentest-llm
if errorlevel 1 exit /b 1
echo.
echo   To register with Ollama:
echo     ollama create pentest-llm -f output\gguf\Modelfile
echo.
echo [+] Export complete.
exit /b 0

:do_eval
echo.
echo [EVAL] Evaluating...
echo ----------------------------------------
mkdir output 2>nul
python evaluation\evaluate.py ^
    --model-name pentest-llm ^
    --test-data  datasets\processed\test.jsonl ^
    --output     output\evaluation_results.json
if errorlevel 1 exit /b 1
echo [+] Evaluation complete.
exit /b 0

:: -------------------------------------------------------------
:done_full
echo.
echo ============================================
echo   Pipeline complete!
echo.
echo   Next steps:
echo     ollama create pentest-llm -f output\gguf\Modelfile
echo     ollama run pentest-llm
echo ============================================
echo.
pause
goto :menu

:done
echo.
echo ============================================
echo   Done!
echo ============================================
echo.
pause
goto :menu

:error
echo.
echo ============================================
echo   [ERROR] Something went wrong.
echo   Check the error message above.
echo ============================================
echo.
pause
goto :menu
