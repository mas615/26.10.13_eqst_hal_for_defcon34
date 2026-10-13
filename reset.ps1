param(
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

Write-Host "This deletes EQSTHAL CTF containers, leaderboard data, and service images."
Write-Host "The files in this folder are preserved."
Write-Host "Docker build-cache cleanup is global and may affect other projects."

if (-not $Yes) {
    $confirmation = Read-Host "Type RESET to continue"
    if ($confirmation -cne "RESET") {
        Write-Host "Canceled."
        exit 0
    }
}

docker compose down --volumes --rmi all --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "Failed to remove EQSTHAL CTF Docker resources."
}

docker builder prune --all --force
if ($LASTEXITCODE -ne 0) {
    throw "EQSTHAL CTF was removed, but Docker build-cache cleanup failed."
}

Write-Host "EQSTHAL CTF Docker state was removed. Project files were preserved."
Write-Host "Run start.cmd to download and build everything again."
