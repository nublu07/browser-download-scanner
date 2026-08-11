@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "config.ini" (
    if exist "config.ini.example" copy /Y "config.ini.example" "config.ini" >nul
)

if not exist ".venv\Scripts\pythonw.exe" (
    echo Сначала запустите install.bat
    exit /b 1
)

for /f "tokens=2 delims=," %%a in ('wmic process where "name='pythonw.exe' and CommandLine like '%%scanner.py%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
    exit /b 0
)

start "" /min "%~dp0.venv\Scripts\pythonw.exe" "%~dp0scanner.py"
