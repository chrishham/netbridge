# Build Network Bridge executable
# Run from netbridge-agent directory: .\scripts\build.ps1

$ErrorActionPreference = "Stop"

Write-Host "Building Network Bridge Agent..." -ForegroundColor Cyan

# Ensure we're in the netbridge-agent directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
Push-Location $agentDir

try {
    # Build with PyInstaller
    uv run --native-tls pyinstaller netbridge-agent.spec --clean --noconfirm

    $exePath = Join-Path $agentDir "dist\netbridge.exe"
    if (Test-Path $exePath) {
        $size = (Get-Item $exePath).Length / 1MB
        Write-Host "`nBuild successful!" -ForegroundColor Green
        Write-Host "Output: $exePath"
        Write-Host "Size: $([math]::Round($size, 2)) MB"
    } else {
        Write-Host "`nBuild failed - executable not found" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}
