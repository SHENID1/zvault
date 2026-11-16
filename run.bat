@echo off
chcp 65001 >nul
title ZCode Secret Masking Proxy
cd /d "%~dp0"

set "PYTHON_EXE="

:: 1. Check local AppData Python 3.13
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
)

:: 2. Check other Python versions in AppData
if not defined PYTHON_EXE (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

:: 3. Check Windows py launcher
if not defined PYTHON_EXE (
    where py >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=py"
)

:: 4. Check python in PATH
if not defined PYTHON_EXE (
    where python >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=python"
)

if not defined PYTHON_EXE (
    echo [ОШИБКА] Не удалось найти Python! Убедитесь, что Python установлен.
    pause
    exit /b 1
)

echo Запуск ZCode Secret Masking Proxy через: %PYTHON_EXE%
echo Адрес сервера: http://127.0.0.1:8765
echo.
"%PYTHON_EXE%" server.py
pause
