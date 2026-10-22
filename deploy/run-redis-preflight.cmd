@echo off
setlocal
cd /d "%~dp0.."
python deploy\run-redis-preflight.py %*
exit /b %ERRORLEVEL%
