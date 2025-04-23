@echo off
setlocal EnableDelayedExpansion

echo Starting boot.img extraction...

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python is not installed or not in PATH. Please install Python.
    pause
    exit /b 1
)

:: Check if unpack.py exists
if not exist "unpack.py" (
    echo ERROR: unpack.py not found in current directory.
    pause
    exit /b 1
)

:: Check if boot.img exists
if not exist "boot.img" (
    echo ERROR: boot.img not found in current directory.
    pause
    exit /b 1
)

:: Run the extraction command
echo Running: python unpack.py extract boot.img
python unpack.py extract boot.img
if %ERRORLEVEL% neq 0 (
    echo ERROR: Extraction failed. Check the output for details.
    pause
    exit /b 1
)

:: Check if output directory exists
if exist "output" (
    echo Extraction completed. Files are in the 'output' directory.
    dir output
) else (
    echo WARNING: Output directory not found. Extraction may have failed.
)

pause
exit /b 0
