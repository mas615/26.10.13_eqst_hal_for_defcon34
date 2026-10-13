$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $projectRoot "compose.yaml"

docker info *> $null
docker compose -f $composeFile config --quiet
docker compose -f $composeFile up -d --build

Write-Host ""
Write-Host "EQSTHAL HalCompat V2 started."
Write-Host "Public: http://localhost:22080/"
Write-Host "For team access, configure the public URLs in compose.yaml."
Write-Host "Admin:  http://127.0.0.1:22079/admin"
docker compose -f $composeFile ps
