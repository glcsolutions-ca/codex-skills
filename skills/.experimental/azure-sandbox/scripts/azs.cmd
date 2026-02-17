@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "ENTRY=%SCRIPT_DIR%azs_main.py"

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%ENTRY%" %*
  exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%ENTRY%" %*
  exit /b %ERRORLEVEL%
)

echo ERROR: Python runtime not found. Install Python 3 to run azs. 1>&2
exit /b 1
