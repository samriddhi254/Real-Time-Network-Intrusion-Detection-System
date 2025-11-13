@echo off
echo Starting ML-based Encrypted Network Traffic Anomaly Detection System...
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate

REM Install requirements if needed
echo Checking dependencies...
pip install -r requirements.txt

REM Check if model files exist
if not exist "xgb_model.pkl" (
    echo.
    echo WARNING: ML model files not found!
    echo Run training.py first to create the model files.
    echo You can use the demo mode for now.
    echo.
)

REM Start the Flask application
echo.
echo Starting Flask application...
echo Navigate to http://localhost:5000 in your browser
echo Press Ctrl+C to stop the server
echo.

python app.py

pause