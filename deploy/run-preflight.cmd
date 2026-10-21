@echo off
setlocal

cd /d "%~dp0.."

python deploy\run-preflight.py

exit /b %ERRORLEVEL%