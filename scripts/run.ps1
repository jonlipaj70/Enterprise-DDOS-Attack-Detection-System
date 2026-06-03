Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host ".venv was not found. Running setup first..."
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "setup.ps1")
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

$env:PYTHONPATH = $ProjectRoot
Write-Host "Starting API and dashboard on http://localhost:8000/?ui=enterprise"
& (Join-Path $ProjectRoot ".venv\Scripts\python.exe") -m src.api.server
