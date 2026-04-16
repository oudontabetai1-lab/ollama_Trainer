@echo off
:: ============================================================
:: generate_dataset.bat — データセット生成 (ダブルクリックで実行)
:: ============================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

title Pentest LLM — データセット生成

echo.
echo ============================================
echo  Pentest LLM — データセット生成
echo ============================================
echo.

:: ── venv チェック・アクティベート ────────────────────────────
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [+] 仮想環境をアクティベートしました
) else (
    echo [!] .venv が見つかりません。setup_windows.bat を先に実行してください
    echo.
    pause
    exit /b 1
)

:: ── 出力ディレクトリ作成 ───────────────────────────────────
mkdir datasets\processed 2>nul
mkdir output\logs        2>nul

echo.
echo [STEP 1/3] データセット生成中...
echo ----------------------------------------
python datasets\synthetic\generate_dataset.py ^
    --format alpaca ^
    --output datasets\synthetic\pentest_dataset.json ^
    --split
if errorlevel 1 goto :error

echo.
echo [STEP 2/3] データセット拡張中 (エンコード変形・言い換え)...
echo ----------------------------------------
python datasets\synthetic\augment_dataset.py ^
    --input  datasets\synthetic\pentest_dataset.json ^
    --output datasets\processed\pentest_augmented.json
if errorlevel 1 goto :error

echo.
echo [STEP 3/3] 拡張データセットを train/val/test に分割中...
echo ----------------------------------------
python -c ^
"import json,random,pathlib; ^
data=json.load(open('datasets/processed/pentest_augmented.json',encoding='utf-8')); ^
random.seed(42); random.shuffle(data); n=len(data); ^
splits={'train':data[:int(n*0.85)],'val':data[int(n*0.85):int(n*0.95)],'test':data[int(n*0.95):]}; ^
[open(f'datasets/processed/{k}.jsonl','w',encoding='utf-8').writelines(json.dumps(v,ensure_ascii=False)+'\n' for v in vs) or print(f'  {k}: {len(vs)} samples') for k,vs in splits.items()]"
if errorlevel 1 goto :error

echo.
echo ============================================
echo  完了！
echo  datasets\synthetic\pentest_dataset.json
echo  datasets\processed\pentest_augmented.json
echo  datasets\processed\train.jsonl / val.jsonl / test.jsonl
echo ============================================
echo.
pause
exit /b 0

:error
echo.
echo [ERROR] エラーが発生しました。上記のメッセージを確認してください。
echo.
pause
exit /b 1
