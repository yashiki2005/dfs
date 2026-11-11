@echo off
rem dfs5svc.cmd - Windows launcher, same role as the POSIX "dfs5svc" script.
rem Uses DFS5CLI_PYTHON when set, otherwise "python" from PATH.
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
if defined DFS5CLI_PYTHON (
    "%DFS5CLI_PYTHON%" -m dfs5.svc %*
) else (
    python -m dfs5.svc %*
)
exit /b %ERRORLEVEL%
