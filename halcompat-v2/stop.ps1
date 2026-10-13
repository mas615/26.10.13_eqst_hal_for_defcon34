$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $projectRoot "compose.yaml"

docker compose -f $composeFile stop
Write-Host "EQSTHAL HalCompat V2 stopped. Existing EQSTHAL services were not changed."
