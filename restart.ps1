$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    docker desktop start
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start Docker Desktop."
    }
}

docker compose restart
if ($LASTEXITCODE -ne 0) {
    throw "Failed to restart EQSTHAL CTF containers."
}

Write-Host "EQSTHAL CTF restarted."
Write-Host "Local:     http://localhost:21080/"
Write-Host "Admin:     http://127.0.0.1:21079/admin"
Write-Host "For team access, configure PUBLIC_HOST in compose.yaml."
docker compose ps
