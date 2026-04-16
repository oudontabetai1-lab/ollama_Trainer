@echo off
:: ============================================================
:: run_pipeline.bat — ファインチューニング パイプライン
::                    (ダブルクリックで実行)
:: ============================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

title Pentest LLM — パイプライン

:menu
cls
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Pentest LLM  Fine-tuning Pipeline      ║
echo  ║   (Ollama / qwen2.5-coder:3b ベース)     ║
echo  ╚══════════════════════════════════════════╝
echo.
echo   1. 全パイプライン実行（推奨）
echo      データセット生成 → 学習 → エクスポート → 評価
echo.
echo   2. データセット生成のみ
echo.
echo   3. 学習のみ
echo      ※ 事前にデータセット生成が必要です
echo.
echo   4. Ollama へのエクスポートのみ
echo      ※ 事前に学習が必要です
echo.
echo   5. 評価のみ
echo      ※ 事前にエクスポートが必要です
echo.
echo   Q. 終了
echo.
set /p CHOICE="番号を入力してください: "

if /i "%CHOICE%"=="1" goto :pipeline_full
if /i "%CHOICE%"=="2" goto :step_dataset
if /i "%CHOICE%"=="3" goto :step_train
if /i "%CHOICE%"=="4" goto :step_export
if /i "%CHOICE%"=="5" goto :step_eval
if /i "%CHOICE%"=="q" exit /b 0
if /i "%CHOICE%"=="Q" exit /b 0

echo.
echo  [!] 無効な選択です。1〜5 または Q を入力してください。
timeout /t 2 >nul
goto :menu

:: ─────────────────────────────────────────────────────────────
:activate_venv
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [+] 仮想環境をアクティベートしました
    exit /b 0
)
echo [ERROR] .venv が見つかりません。先に setup_windows.bat を実行してください。
pause
exit /b 1

:: ─────────────────────────────────────────────────────────────
:pipeline_full
cls
echo.
echo ============================================
echo  全パイプライン実行
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

:: ─────────────────────────────────────────────────────────────
:step_dataset
cls
echo.
echo ============================================
echo  データセット生成
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_dataset
if errorlevel 1 goto :error
goto :done

:: ─────────────────────────────────────────────────────────────
:step_train
cls
echo.
echo ============================================
echo  学習
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_train
if errorlevel 1 goto :error
goto :done

:: ─────────────────────────────────────────────────────────────
:step_export
cls
echo.
echo ============================================
echo  Ollama へのエクスポート
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_export
if errorlevel 1 goto :error
goto :done

:: ─────────────────────────────────────────────────────────────
:step_eval
cls
echo.
echo ============================================
echo  評価
echo ============================================
call :activate_venv
if errorlevel 1 exit /b 1
call :do_eval
if errorlevel 1 goto :error
goto :done

:: ─────────────────────────────────────────────────────────────
:: 各ステップの実処理（サブルーチン）
:: ─────────────────────────────────────────────────────────────

:do_dataset
echo.
echo [STEP] データセット生成中...
echo ----------------------------------------
mkdir datasets\processed 2>nul
mkdir output\logs        2>nul

python datasets\synthetic\generate_dataset.py ^
    --format alpaca ^
    --output datasets\synthetic\pentest_dataset.json ^
    --split
if errorlevel 1 exit /b 1

echo.
echo [STEP] データセット拡張中 (エンコード変形・言い換え)...
echo ----------------------------------------
python datasets\synthetic\augment_dataset.py ^
    --input  datasets\synthetic\pentest_dataset.json ^
    --output datasets\processed\pentest_augmented.json
if errorlevel 1 exit /b 1

echo.
echo [STEP] 拡張データセットを train/val/test に分割中...
python -c ^
"import json,random,pathlib; ^
data=json.load(open('datasets/processed/pentest_augmented.json',encoding='utf-8')); ^
random.seed(42); random.shuffle(data); n=len(data); ^
splits={'train':data[:int(n*0.85)],'val':data[int(n*0.85):int(n*0.95)],'test':data[int(n*0.95):]}; ^
[open(f'datasets/processed/{k}.jsonl','w',encoding='utf-8').writelines(json.dumps(v,ensure_ascii=False)+'\n' for v in vs) or print(f'  {k}: {len(vs)} samples') for k,vs in splits.items()]"
if errorlevel 1 exit /b 1

echo [+] データセット生成完了
exit /b 0

:do_train
echo.
echo [STEP] 学習開始...
echo ----------------------------------------
mkdir output\models      2>nul
mkdir output\checkpoints 2>nul
mkdir output\logs        2>nul

python training\train.py ^
    --config config\training_config.yaml ^
    --train  datasets\processed\train.jsonl ^
    --val    datasets\processed\val.jsonl
if errorlevel 1 exit /b 1

echo [+] 学習完了
exit /b 0

:do_export
echo.
echo [STEP] GGUF 変換 + Modelfile 生成中...
echo ----------------------------------------
mkdir output\gguf 2>nul

python training\export_to_ollama.py ^
    --adapter-dir output\models ^
    --output-dir  output\gguf ^
    --config      config\training_config.yaml ^
    --model-name  pentest-llm
if errorlevel 1 exit /b 1

echo.
echo  Ollama にモデルを登録するには:
echo    ollama create pentest-llm -f output\gguf\Modelfile
echo.
echo [+] エクスポート完了
exit /b 0

:do_eval
echo.
echo [STEP] 評価中...
echo ----------------------------------------
mkdir output 2>nul

python evaluation\evaluate.py ^
    --model-name pentest-llm ^
    --test-data  datasets\processed\test.jsonl ^
    --output     output\evaluation_results.json
if errorlevel 1 exit /b 1

echo [+] 評価完了
exit /b 0

:: ─────────────────────────────────────────────────────────────
:done_full
echo.
echo ============================================
echo  全パイプライン完了！
echo.
echo  次のステップ:
echo    ollama create pentest-llm -f output\gguf\Modelfile
echo    ollama run pentest-llm
echo ============================================
echo.
pause
goto :menu

:done
echo.
echo ============================================
echo  完了！
echo ============================================
echo.
pause
goto :menu

:error
echo.
echo ============================================
echo  [ERROR] エラーが発生しました。
echo  上記のエラーメッセージを確認してください。
echo ============================================
echo.
pause
goto :menu
