@echo off
setlocal
cd /d "%~dp0.."
python deploy\run-auth-rotation-execute.py %*
exit /b %ERRORLEVEL%
