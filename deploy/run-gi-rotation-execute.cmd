@echo off
setlocal

cd /d "%~dp0.."

python deploy\run-gi-rotation-execute.py %*

exit /b %ERRORLEVEL%
