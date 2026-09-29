@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Prefer entropy pre-warmed gprun.bat to prevent Windows SCardSvr 5s transaction timeout
if exist "%SCRIPT_DIR%tools\gprun.bat" (
    set "GP_CMD=%SCRIPT_DIR%tools\gprun.bat"
) else if exist "%SCRIPT_DIR%..\gprun.bat" (
    set "GP_CMD=%SCRIPT_DIR%..\gprun.bat"
) else (
    set "GP_CMD=gp"
    where gp >nul 2>nul
    if %errorlevel% neq 0 (
        if exist "%SCRIPT_DIR%tools\gp.exe" (
            set "GP_CMD=%SCRIPT_DIR%tools\gp.exe"
        ) else if exist "%SCRIPT_DIR%..\gp.exe" (
            set "GP_CMD=%SCRIPT_DIR%..\gp.exe"
        )
    )
)

echo ============================================================
echo  Deploying SmartPGP-J3R452-Curve25519 to Card
echo ============================================================

echo [1/2] Loading Curve25519 hardware library CAP...
"%GP_CMD%" -r PCD --load "%SCRIPT_DIR%lib\Curve25519.cap"
if %errorlevel% neq 0 (
    echo [NOTE] Curve25519.cap might already be loaded on the card. Continuing...
)

echo.
echo [2/2] Installing SmartPGP Applet CAP...
"%GP_CMD%" -r PCD --install "%SCRIPT_DIR%dist\SmartPGPApplet.cap"

if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo  INSTALLATION SUCCESSFUL!
    echo  Applet AID: D276000124010304AFAF000000000000
    echo ============================================================
) else (
    echo.
    echo ============================================================
    echo  INSTALLATION FAILED! Check error output above.
    echo ============================================================
)

endlocal
