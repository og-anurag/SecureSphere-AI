@echo off
setlocal
cd /d "%~dp0.."
python desktop\launch_watcher.py
echo.
pause