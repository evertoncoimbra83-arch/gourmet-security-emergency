@echo off
setlocal

cd /d "%~dp0.."

python deploy\run-gi-rotation.py %*

exit /b %ERRORLEVEL%
