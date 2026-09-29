<#
.SYNOPSIS
    Installs Curve25519 library and SmartPGP applet on J3R452 card via GlobalPlatformPro.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$gpCmd = "gp"
if (-not (Get-Command "gp" -ErrorAction SilentlyContinue)) {
    $parentGp = Join-Path (Split-Path -Parent $ScriptDir) "gp.exe"
    if (Test-Path $parentGp) {
        $gpCmd = $parentGp
    } else {
        Write-Error "gp.exe not found in PATH or parent directory."
        exit 1
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Deploying SmartPGP-J3R452-Curve25519 to Card" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "[1/2] Loading Curve25519 hardware library CAP..." -ForegroundColor Yellow
& $gpCmd -r PCD --load (Join-Path $ScriptDir "lib\Curve25519.cap")
if ($LASTEXITCODE -ne 0) {
    Write-Host "[NOTE] Curve25519.cap might already be loaded on the card. Continuing..." -ForegroundColor Gray
}

Write-Host ""
Write-Host "[2/2] Installing SmartPGP Applet CAP..." -ForegroundColor Yellow
& $gpCmd -r PCD --install (Join-Path $ScriptDir "dist\SmartPGPApplet.cap")

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " INSTALLATION SUCCESSFUL!" -ForegroundColor Green
    Write-Host " Applet AID: D276000124010304AFAF000000000000" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " INSTALLATION FAILED! Check error output above." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    exit 1
}
