@echo off
echo ============================================
echo   CyberShield - Starting Backend Server
echo ============================================

:: Check if pip packages are installed
python -c "import fastapi" 2>nul
if errorlevel 1 (
    echo [*] Installing dependencies...
    python -m pip install -r requirements.txt
)

echo.
echo [*] Starting FastAPI server on http://localhost:8000
echo [*] Press Ctrl+C to stop
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
