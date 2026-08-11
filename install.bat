@echo off
chcp 65001 >nul
setlocal

set "DIR=%~dp0"
cd /d "%DIR%"

where py >nul 2>&1
if %ERRORLEVEL%==0 (
    set "PY=py -3"
) else (
    set "PY=python"
)

echo === Browser Download Scanner — установка ===

if not exist "config.ini" (
    copy /Y "config.ini.example" "config.ini" >nul
    echo Создан config.ini из шаблона.
)

if not exist ".venv" (
    echo Создание виртуального окружения...
    %PY% -m venv .venv
)

call ".venv\Scripts\activate.bat"
python -m pip install -q --upgrade pip
pip install -q -r requirements.txt

echo.
echo Укажите API-ключ VirusTotal в config.ini ([virustotal] api_key = ...)
echo.
set /p STARTUP="Включить автозапуск при входе в Windows? (y/n): "
if /i "%STARTUP%"=="y" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0scanner.py" --startup on
) else (
    "%~dp0.venv\Scripts\python.exe" "%~dp0scanner.py" --startup off
)

echo.
echo Запуск мониторинга...
call "%~dp0start.bat"

endlocal
