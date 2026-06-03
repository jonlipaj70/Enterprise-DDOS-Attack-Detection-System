Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

function Invoke-ProjectPython {
    param([string[]]$Arguments)
    & (Join-Path $ProjectRoot ".venv\Scripts\python.exe") @Arguments
}

function Get-BootstrapPython {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return @{ Command = "py"; Arguments = @("-3") }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @{ Command = $python.Source; Arguments = @() }
    }

    throw "Python 3.11+ was not found. Install Python from https://www.python.org/downloads/ and rerun this script."
}

Write-Host "== Enterprise DDoS setup =="
Write-Host "Project: $ProjectRoot"

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    $bootstrap = Get-BootstrapPython
    Write-Host "Creating .venv..."
    & $bootstrap.Command @($bootstrap.Arguments + @("-m", "venv", ".venv"))
}

Write-Host "Upgrading pip..."
Invoke-ProjectPython @("-m", "pip", "install", "--upgrade", "pip")

Write-Host "Installing dependencies..."
Invoke-ProjectPython @("-m", "pip", "install", "-r", "requirements.txt")

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

New-Item -ItemType Directory -Force "models" | Out-Null
New-Item -ItemType Directory -Force "data\uploads\cicddos2019" | Out-Null

Write-Host "Initializing SQLite database..."
Invoke-ProjectPython @(
    "-c",
    "from src.config.settings import get_settings; from src.storage.database import Database; db=Database(get_settings().database.database_url); db.initialize(); print(f'Initialized {db.path}')"
)

$createAdmin = Read-Host "Create the first Admin account now? [y/N]"
if ($createAdmin -match "^[Yy]") {
    Invoke-ProjectPython @("-m", "src.cli.create_admin")
}

Write-Host ""
Write-Host "Setup complete."
Write-Host "Run: powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1"
Write-Host "Dashboard: http://localhost:8000/?ui=enterprise"
