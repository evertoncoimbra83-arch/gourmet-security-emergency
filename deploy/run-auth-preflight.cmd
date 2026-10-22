@echo off
setlocal
cd /d "%~dp0.."
python deploy\run-auth-preflight.py %*
exit /b %ERRORLEVEL%
