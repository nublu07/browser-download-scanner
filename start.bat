@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "config.ini" (
    if exist "config.ini.example" copy /Y "config.ini.example" "config.ini" >nul
)

if not exist ".venv\Scripts\pythonw.exe" (
    echo Сначала запустите install.bat
    pause
    exit /b 1
)

tasklist /FI "IMAGENAME eq pythonw.exe" /FO CSV | find /I "pythonw.exe" >nul
for /f "tokens=2 delims=," %%a in ('wmic process where "name='pythonw.exe' and CommandLine like '%%scanner.py%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
    echo Сканер уже запущен (PID %%a^)
    exit /b 0
)

start "" /min "%~dp0.venv\Scripts\pythonw.exe" "%~dp0scanner.py"
echo Сканер запущен. Лог: %~dp0scanner.log
