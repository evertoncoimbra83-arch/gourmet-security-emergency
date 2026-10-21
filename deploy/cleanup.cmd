@echo off
setlocal

cd /d "%~dp0.."

python deploy\cleanup.py %*

exit /b %ERRORLEVEL%