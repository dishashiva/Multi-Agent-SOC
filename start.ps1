# start.ps1 - SOC-in-a-Box Start Script
# Launches the backend API server and frontend dev server in parallel.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  SOC-in-a-Box" -ForegroundColor Cyan
Write-Host "  Starting services..." -ForegroundColor Gray
Write-Host ""

# --- Backend (FastAPI + uvicorn) ---
Write-Host "  [1/2] Backend  -> http://localhost:8080" -ForegroundColor Yellow
$venvPython = Join-Path $root "venv\Scripts\python.exe"
$backend = Start-Process -PassThru -NoNewWindow -FilePath $venvPython `
    -ArgumentList "-m", "uvicorn", "backend.api_server:app", "--host", "0.0.0.0", "--port", "8080", "--reload" `
    -WorkingDirectory $root

# --- Frontend (Vite dev server) ---
Write-Host "  [2/2] Frontend -> http://localhost:5173" -ForegroundColor Yellow
$frontend = Start-Process -PassThru -NoNewWindow -FilePath "cmd" `
    -ArgumentList "/c", "npm", "run", "dev" `
    -WorkingDirectory "$root\frontend"

Write-Host ""
Write-Host "  All services running. Press Ctrl+C to stop." -ForegroundColor Green
Write-Host ""

# Wait for Ctrl+C, then clean up both processes
try {
    while ($true) { Start-Sleep -Seconds 1 }
}
finally {
    Write-Host ""
    Write-Host "  Stopping services..." -ForegroundColor Gray
    Stop-Process -Id $backend.Id  -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $frontend.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  Done." -ForegroundColor Green
}
