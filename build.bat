@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Check JAVA_HOME and verify javac.exe exists
set "NEED_JDK=0"
if not defined JAVA_HOME set "NEED_JDK=1"
if defined JAVA_HOME (
    if not exist "%JAVA_HOME%\bin\javac.exe" set "NEED_JDK=1"
)

if "%NEED_JDK%"=="1" (
    if exist "%SCRIPT_DIR%..\build_tools\jdk_extracted\jdk-11.0.32.1+1\bin\javac.exe" (
        set "JAVA_HOME=%SCRIPT_DIR%..\build_tools\jdk_extracted\jdk-11.0.32.1+1"
        set "PATH=%SCRIPT_DIR%..\build_tools\jdk_extracted\jdk-11.0.32.1+1\bin;%PATH%"
    )
)

:: Check Ant
where ant >nul 2>nul
if %errorlevel% neq 0 (
    if exist "%SCRIPT_DIR%..\build_tools\ant_extracted\apache-ant-1.10.18\bin\ant.bat" (
        set "ANT_CMD=%SCRIPT_DIR%..\build_tools\ant_extracted\apache-ant-1.10.18\bin\ant.bat"
    ) else (
        echo [ERROR] Apache Ant not found in PATH or build_tools directory.
        pause
        exit /b 1
    )
) else (
    set "ANT_CMD=ant"
)

echo ============================================================
echo  Building SmartPGP-J3R452-Curve25519 Applet
echo ============================================================
call "%ANT_CMD%" -f "%SCRIPT_DIR%build.xml" convert

if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo  BUILD SUCCESS!
    echo  CAP file: %SCRIPT_DIR%dist\SmartPGPApplet.cap
    echo ============================================================
) else (
    echo.
    echo ============================================================
    echo  BUILD FAILED! Please check error output above.
    echo ============================================================
)

endlocal
