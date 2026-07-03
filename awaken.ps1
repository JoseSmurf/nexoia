# awaken.ps1 - Acorda o NexoIA
# Uso: .\awaken.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== NexoIA - Despertar ===" -ForegroundColor Cyan
Write-Host ""

# Encontra cargo
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
if (-not (Test-Path $cargo)) {
    $cargo = "cargo"
}

# Build primeiro
Write-Host "Buildando NexoIA..." -ForegroundColor Yellow
& $cargo build --bin awaken 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build falhou!" -ForegroundColor Red
    exit 1
}

Write-Host "Build OK. Iniciando despertar..." -ForegroundColor Green
Write-Host ""

# Roda o awaken
& $cargo run --bin awaken
