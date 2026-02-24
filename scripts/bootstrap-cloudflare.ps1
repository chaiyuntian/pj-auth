param(
  [string]$DatabaseName = "pj-auth-db",
  [string]$DatabaseLocation = "enam",
  [string]$SecretsFile = ".prod.secrets.psd1",
  [switch]$SkipSecrets
)

$ErrorActionPreference = "Stop"

function Invoke-LoggedCommand {
  param([string]$Command)
  Write-Host ">> $Command"
  Invoke-Expression $Command
}

Write-Host "Checking Wrangler authentication"
Invoke-LoggedCommand "npx wrangler whoami | Out-Null"

Write-Host "Resolving D1 database: $DatabaseName"
$dbListRaw = Invoke-Expression "npx wrangler d1 list --json"
$dbList = $dbListRaw | ConvertFrom-Json
$existing = $dbList | Where-Object { $_.name -eq $DatabaseName } | Select-Object -First 1
$databaseId = $null

if ($existing) {
  $databaseId = $existing.uuid
  Write-Host "Using existing D1 database $DatabaseName ($databaseId)"
} else {
  Write-Host "Creating D1 database $DatabaseName in $DatabaseLocation"
  $createOut = Invoke-Expression "npx wrangler d1 create $DatabaseName --location $DatabaseLocation"
  if ($createOut -match 'database_id = "([^"]+)"') {
    $databaseId = $Matches[1]
  } else {
    throw "Failed to parse database_id from wrangler output."
  }
  Write-Host "Created D1 database $DatabaseName ($databaseId)"
}

if (-not $databaseId) {
  throw "Unable to determine D1 database_id."
}

Write-Host "Updating wrangler.toml database_id"
$wranglerPath = "wrangler.toml"
$wranglerRaw = Get-Content -Path $wranglerPath -Raw
$updatedWrangler = [regex]::Replace($wranglerRaw, 'database_id\s*=\s*"[^"]*"', "database_id = `"$databaseId`"", 1)
if ($updatedWrangler -ne $wranglerRaw) {
  Set-Content -Path $wranglerPath -Value $updatedWrangler -NoNewline
  Write-Host "wrangler.toml updated with database_id=$databaseId"
} else {
  Write-Warning "Could not locate database_id line in wrangler.toml; update manually if needed."
}

if (-not $SkipSecrets) {
  if (Test-Path $SecretsFile) {
    Write-Host "Applying secrets from $SecretsFile"
    $secrets = Import-PowerShellDataFile $SecretsFile
    foreach ($entry in $secrets.GetEnumerator()) {
      $name = $entry.Key
      $value = [string]$entry.Value
      if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Warning "Skipping empty secret value for $name"
        continue
      }
      Write-Host "Setting secret: $name"
      $value | npx wrangler secret put $name | Out-Null
    }
  } else {
    Write-Warning "Secrets file $SecretsFile not found. Skipping secret upload."
  }
} else {
  Write-Host "Skipping secret upload (--SkipSecrets)"
}

Write-Host "Applying remote D1 migrations"
Invoke-LoggedCommand "npx wrangler d1 migrations apply $DatabaseName --remote"

Write-Host "Deploying Worker"
Invoke-LoggedCommand "npx wrangler deploy"

Write-Host "Bootstrap complete."
