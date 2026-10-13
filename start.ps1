$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Start Docker Desktop first."
}

Write-Host "[EQSTHAL CTF] Checking challenge images..."
docker compose pull --ignore-buildable
if ($LASTEXITCODE -ne 0) {
    throw "Failed to pull challenge images."
}

Write-Host "[EQSTHAL CTF] Starting 20 challenge services and serving 7 file-only challenges..."
docker compose up -d --build --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Failed to start EQSTHAL CTF containers."
}

$portalReady = $false
$adminReady = $false
$deadline = (Get-Date).AddMinutes(2)
do {
    try {
        $portalResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri "http://127.0.0.1:21080/healthz" `
            -TimeoutSec 3
        $portalReady = $portalResponse.StatusCode -eq 200
    } catch {}

    try {
        $adminResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri "http://127.0.0.1:21079/healthz" `
            -TimeoutSec 3
        $adminReady = $adminResponse.StatusCode -eq 200
    } catch {}

    if ($portalReady -and $adminReady) {
        break
    }

    if ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
    }
} while ((Get-Date) -lt $deadline)

if (-not $portalReady -or -not $adminReady) {
    throw "The public portal or local admin did not become ready in time."
}

Write-Host ""
Write-Host "EQSTHAL CTF is ready."
Write-Host "Local:     http://localhost:21080/"
Write-Host "Admin:     http://127.0.0.1:21079/admin"
Write-Host "For team access, configure PUBLIC_HOST in compose.yaml."
docker compose ps
