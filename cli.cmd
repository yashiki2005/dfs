@echo off
setlocal
set SELF_DIR=%~dp0
if exist "%SELF_DIR%.venv\Scripts\python.exe" (
    "%SELF_DIR%.venv\Scripts\python.exe" -m dfs.simple_cli %*
    exit /b %ERRORLEVEL%
)
python -m dfs.simple_cli %*
