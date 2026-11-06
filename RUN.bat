@echo off
setlocal
set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "VENV_PYTHON=%VENV%\Scripts\python.exe"
cd /d "%ROOT%"

if exist "%VENV_PYTHON%" goto check_dependencies

where py >nul 2>&1
if errorlevel 1 goto python_fallback
py -3 -c "import sys; raise SystemExit(sys.version_info < (3, 9))" >nul 2>&1
if errorlevel 1 goto python_fallback
py -3 -m venv "%VENV%"
if errorlevel 1 goto venv_failed
goto check_dependencies

:python_fallback
where python >nul 2>&1
if errorlevel 1 goto no_python
python -c "import sys; raise SystemExit(sys.version_info < (3, 9))" >nul 2>&1
if errorlevel 1 goto no_python
python -m venv "%VENV%"
if errorlevel 1 goto venv_failed
goto check_dependencies

:check_dependencies
"%VENV_PYTHON%" -c "import PIL" >nul 2>&1
if not errorlevel 1 goto run_server
echo Installing Python dependencies ...
"%VENV_PYTHON%" -m pip install --disable-pip-version-check -r "%ROOT%requirements.txt"
if errorlevel 1 goto install_failed
goto run_server

:run_server
"%VENV_PYTHON%" web\server.py --open-browser %*
exit /b %errorlevel%

:venv_failed
echo Could not create %VENV%. Ensure venv is available and the directory is writable. 1>&2
exit /b 1

:install_failed
echo Could not install Python dependencies. Check your network connection, or run: 1>&2
echo   "%VENV_PYTHON%" -m pip install -r "%ROOT%requirements.txt" 1>&2
exit /b 1

:no_python
echo Python 3.9 or newer is required. Install it from https://www.python.org/ and try again. 1>&2
exit /b 1
