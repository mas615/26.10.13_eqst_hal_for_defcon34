$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

docker compose down --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Failed to stop EQSTHAL CTF containers."
}

Write-Host "EQSTHAL CTF stopped. Leaderboard data and images are preserved."
