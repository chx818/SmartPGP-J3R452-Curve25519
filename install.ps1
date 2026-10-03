# Generic single-applet installer. Pass Python-style options, e.g. --reader PCD.
$ErrorActionPreference = "Stop"
& python (Join-Path $PSScriptRoot "tools/deploy_verified.py") @args
exit $LASTEXITCODE
