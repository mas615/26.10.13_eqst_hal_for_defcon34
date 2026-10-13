$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $projectRoot "compose.yaml"

docker compose -f $composeFile restart
docker compose -f $composeFile ps
