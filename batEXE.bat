@echo off
setlocal EnableDelayedExpansion

:: Use the current directory of the batch file
set "SCRIPT_DIR=%~dp0"
set "EXE_PATH=%SCRIPT_DIR%unpack.exe"
set "BOOT_IMG=%SCRIPT_DIR%boot.img"
set "OUTPUT_DIR=%SCRIPT_DIR%output"
set "SEVEN_ZIP=%SCRIPT_DIR%7z.exe"
set "LOG_FILE=%SCRIPT_DIR%extraction_log.txt"

:: Check if executable exists
if not exist "%EXE_PATH%" (
    echo Error: unpack.exe not found in the current directory
    pause
    exit /b 1
)

:: Check if boot.img exists
if not exist "%BOOT_IMG%" (
    echo Error: boot.img not found in the current directory
    pause
    exit /b 1
)

:: Check if 7z.exe exists
if not exist "%SEVEN_ZIP%" (
    echo Warning: 7z.exe not found in the current directory. Ensure it's bundled with the executable or available.
)

:: Create output directory
if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

:: Log start time
echo Starting boot image extraction at %date% %time% >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

:: Run the executable
echo Running: unpack.exe extract "%BOOT_IMG%" --output-dir "%OUTPUT_DIR%" --skip-avb --debug-cpio
"%EXE_PATH%" extract "%BOOT_IMG%" --output-dir "%OUTPUT_DIR%" --skip-avb --debug-cpio >> "%LOG_FILE%" 2>&1

:: Check if extraction was successful
if %ERRORLEVEL% equ 0 (
    echo Extraction completed. Files are in: %OUTPUT_DIR%
    echo Extraction completed at %date% %time% >> "%LOG_FILE%"
    echo. >> "%LOG_FILE%"
    echo Directory contents:
    dir "%OUTPUT_DIR%" /s >> "%LOG_FILE%"
    dir "%OUTPUT_DIR%" /s
) else (
    echo Error: Extraction failed. Check %LOG_FILE% for details.
    echo Extraction failed at %date% %time% >> "%LOG_FILE%"
)

:: Pause to view output
pause
endlocal
