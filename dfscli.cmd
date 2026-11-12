@echo off
rem dfscli.cmd - Windows launcher, same role as the POSIX "dfscli" script.
rem Uses DFSCLI_PYTHON when set, otherwise "python" from PATH.
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
if defined DFSCLI_PYTHON (
    "%DFSCLI_PYTHON%" -m dfs.cli_main %*
) else (
    python -m dfs.cli_main %*
)
exit /b %ERRORLEVEL%
