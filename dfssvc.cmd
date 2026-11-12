@echo off
rem dfssvc.cmd - Windows launcher, same role as the POSIX "dfssvc" script.
rem Uses DFSCLI_PYTHON when set, otherwise "python" from PATH.
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
if defined DFSCLI_PYTHON (
    "%DFSCLI_PYTHON%" -m dfs.svc %*
) else (
    python -m dfs.svc %*
)
exit /b %ERRORLEVEL%
