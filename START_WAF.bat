@echo off
echo.
echo ==================================================
echo    AI-Powered Web Application Firewall
echo ==================================================
echo.

:: Create logs folder if missing
if not exist logs mkdir logs

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo ERROR: Python not found. Please install Python from https://python.org
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)

echo Python found. Installing required packages...
echo.
%PYTHON% -m pip install fastapi uvicorn aiosqlite httpx jinja2 python-multipart pydantic --quiet

echo.
echo Starting WAF server...
echo.
echo  Dashboard --^> http://localhost:8000
echo  API Docs  --^> http://localhost:8000/api/docs
echo.
echo Opening browser in 3 seconds...
timeout /t 3 /nobreak >nul
start http://localhost:8000

%PYTHON% main.py

pause
