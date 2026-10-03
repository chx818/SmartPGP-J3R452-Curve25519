@echo off
setlocal
python "%~dp0tools\deploy_verified.py" %*
exit /b %errorlevel%
