@echo off
setlocal
set "JAVA_EXE=%~dp0..\..\build_tools\jdk_extracted\jdk-11.0.32.1+1\bin\java.exe"
if not exist "%JAVA_EXE%" set "JAVA_EXE=java"

set "GP_JAR=%~dp0gp.exe"
if not exist "%GP_JAR%" set "GP_JAR=%~dp0..\..\gp.exe"

"%JAVA_EXE%" -cp "%~dp0;%GP_JAR%" GPRunner %*
