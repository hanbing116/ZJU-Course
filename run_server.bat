@echo off
rem zjucourse local server launcher (double-click to run)
rem Data dir: this folder (session.dat is saved here too)
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel%==0 (
    python server.py %*
    goto end
)

where py >nul 2>nul
if %errorlevel%==0 (
    py server.py %*
    goto end
)

if exist "D:\ANACONDA\python.exe" (
    "D:\ANACONDA\python.exe" server.py %*
    goto end
)

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" server.py %*
    goto end
)

echo Python not found. Please install Python 3 first,
echo or just use the original zjucourse-server.exe.

:end
pause
