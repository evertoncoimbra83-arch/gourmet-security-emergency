@echo off
setlocal
cd /d "%~dp0.."
python deploy\run-gi-preflight.py %*
exit /b %ERRORLEVEL%
