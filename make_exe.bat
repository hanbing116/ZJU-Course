@echo off
rem ============================================================
rem  Rebuild ZJU-Course.exe (onefile, windowed, icon = ZC.jpg)
rem  Usage: double-click this file. It must run from the repo root.
rem  Prereq: a Python env with pyinstaller, pywebview, pillow.
rem  If a local "build-env" folder exists (Scripts\python.exe), it
rem  is used automatically; otherwise falls back to system python.
rem ============================================================
setlocal
cd /d "%~dp0"
set ROOT=%~dp0
set ROOT=%ROOT:~0,-1%

rem --- pick python: prefer local build-env, else "py", else python ---
set PY=
if exist "%ROOT%\build-env\Scripts\python.exe" set PY=%ROOT%\build-env\Scripts\python.exe
if not defined PY ( where py >nul 2>nul && set PY=py )
if not defined PY ( where python >nul 2>nul && set PY=python )
if not defined PY ( echo No python found. Install python + pyinstaller/pywebview/pillow. & pause & exit /b 1 )

set PIP_CACHE_DIR=%ROOT%\.pipcache

echo [1/3] Refresh icon from ZC.jpg ...
%PY% -c "from PIL import Image; img = Image.open(r'%ROOT%\ZC.jpg').convert('RGBA'); img.save(r'%ROOT%\ZC.ico', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"
if errorlevel 1 ( echo Icon failed & pause & exit /b 1 )

echo [2/3] Building exe (about 30 seconds) ...
%PY% -m PyInstaller --onefile --windowed --name ZJU-Course --icon "%ROOT%\ZC.ico" --add-data "%ROOT%\index.html;." --collect-all webview --distpath "%ROOT%\dist" --workpath "%ROOT%\build" --specpath "%ROOT%\build" "%ROOT%\desktop.py"
if errorlevel 1 ( echo Build failed & pause & exit /b 1 )

echo [3/3] Cleaning intermediate files ...
rd /s /q "%ROOT%\build" 2>nul
rd /s /q "%ROOT%\.pipcache" 2>nul

echo.
echo Done: %ROOT%\dist\ZJU-Course.exe
pause
