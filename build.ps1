<#
.SYNOPSIS
    Builds SmartPGP-J3R452-Curve25519 applet using Ant and Java Card SDK.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Auto-detect JDK 11 with javac.exe
$needJdk = $false
if (-not $env:JAVA_HOME) {
    $needJdk = $true
} elseif (-not (Test-Path (Join-Path $env:JAVA_HOME "bin\javac.exe"))) {
    $needJdk = $true
}

if ($needJdk) {
    $fallbackJdk = Join-Path (Split-Path -Parent $ScriptDir) "build_tools\jdk_extracted\jdk-11.0.32.1+1"
    if (Test-Path (Join-Path $fallbackJdk "bin\javac.exe")) {
        $env:JAVA_HOME = $fallbackJdk
        $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
    }
}

# Auto-detect Ant
$antCmd = "ant"
if (-not (Get-Command "ant" -ErrorAction SilentlyContinue)) {
    $fallbackAnt = Join-Path (Split-Path -Parent $ScriptDir) "build_tools\ant_extracted\apache-ant-1.10.18\bin\ant.bat"
    if (Test-Path $fallbackAnt) {
        $antCmd = $fallbackAnt
    } else {
        Write-Error "Apache Ant not found in PATH or build_tools directory."
        exit 1
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Building SmartPGP-J3R452-Curve25519 Applet" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

& $antCmd -f (Join-Path $ScriptDir "build.xml") convert

if ($LASTEXITCODE -eq 0) {
    $capPath = Join-Path $ScriptDir "dist\SmartPGPApplet.cap"
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESS!" -ForegroundColor Green
    Write-Host " CAP file: $capPath" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " BUILD FAILED! Check error output above." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    exit 1
}
