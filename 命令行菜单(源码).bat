@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal

set "PY=python"
where py >nul 2>nul && (py -3 -c "" >nul 2>nul && set "PY=py -3")

%PY% ctf.py
pause
