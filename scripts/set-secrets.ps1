param(
  [string]$SecretsFile = ".prod.secrets.psd1"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SecretsFile)) {
  throw "Secrets file '$SecretsFile' not found. Create a PowerShell data file with key/value pairs."
}

$secrets = Import-PowerShellDataFile -Path $SecretsFile
foreach ($key in $secrets.Keys) {
  $value = [string]$secrets[$key]
  if (-not $value) {
    Write-Warning "Skipping empty secret: $key"
    continue
  }
  Write-Host "Uploading secret: $key"
  $value | npx wrangler secret put $key
}

Write-Host "All secrets uploaded."
