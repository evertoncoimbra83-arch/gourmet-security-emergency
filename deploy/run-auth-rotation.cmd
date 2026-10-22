@echo off
setlocal
cd /d "%~dp0.."
python deploy\run-auth-rotation.py %*
exit /b %ERRORLEVEL%
