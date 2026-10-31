@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal

rem 优先用 py -3：它通常指向装了 pycryptodome/sympy 的那个解释器，
rem 而 PATH 里的 python 可能是另一个没装依赖的版本。
set "PY=python"
where py >nul 2>nul && (py -3 -c "" >nul 2>nul && set "PY=py -3")

%PY% -c "import Crypto" >nul 2>nul || (
  echo [提示] 当前解释器缺少 pycryptodome，"自检"里的对称密码题会跑不动。
  echo        补装: %PY% -m pip install pycryptodome rich sympy
  echo.
)

%PY% ctf.py web
pause
