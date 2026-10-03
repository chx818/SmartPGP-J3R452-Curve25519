@echo off
python "%~dp0tools\build_verified.py" %*
exit /b %errorlevel%
