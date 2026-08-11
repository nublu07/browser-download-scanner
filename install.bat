@echo off
chcp 65001 >nul
title Browser Download Scanner — установка
cd /d "%~dp0"

where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")

echo.
echo  ============================================
echo    Browser Download Scanner — установка
echo  ============================================
echo.

if not exist "config.ini" (
    copy /Y "config.ini.example" "config.ini" >nul
    echo [OK] Создан config.ini
)

if not exist ".venv\Scripts\python.exe" (
    echo [*] Создание окружения Python...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ОШИБКА] Не удалось создать venv. Установите Python 3.10+
        pause
        exit /b 1
    )
)

echo [*] Установка зависимостей...
".venv\Scripts\python.exe" -m pip install -q --upgrade pip
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt

echo.
echo  Укажите API-ключ VirusTotal в config.ini
echo  https://www.virustotal.com/gui/my-apikey
echo.
set /p STARTUP="Включить автозапуск при входе в Windows? (y/n): "
if /i "%STARTUP%"=="y" (
    ".venv\Scripts\python.exe" "%~dp0scanner.py" --startup on
) else (
    ".venv\Scripts\python.exe" "%~dp0scanner.py" --startup off
)

echo.
call "%~dp0start.bat"
echo.
echo  Готово! Используйте start.bat / stop.bat / status.bat
echo.
pause
