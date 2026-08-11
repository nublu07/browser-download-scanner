@echo off
chcp 65001 >nul
set "FOUND=0"
for /f "tokens=2 delims=," %%a in ('wmic process where "name='pythonw.exe' and CommandLine like '%%scanner.py%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
    taskkill /PID %%a /F >nul 2>&1
    echo Остановлен процесс %%a
    set "FOUND=1"
)
if "%FOUND%"=="0" echo Сканер не запущен.
