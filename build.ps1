$ErrorActionPreference = "Stop"
& python (Join-Path $PSScriptRoot "tools/build_verified.py") @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
