param(
  [string]$DatabaseName = "pj-auth-db",
  [string]$DatabaseLocation = "enam",
  [switch]$ApplyRoute,
  [string]$CustomDomain = "users.pajamadot.com"
)

$ErrorActionPreference = "Stop"

Write-Host "Creating D1 database '$DatabaseName'..."
$createOutput = npx wrangler d1 create $DatabaseName --location $DatabaseLocation 2>&1
$createOutput | ForEach-Object { Write-Host $_ }

$dbIdLine = $createOutput | Select-String -Pattern 'database_id\s*=\s*"([^"]+)"' | Select-Object -First 1
if ($dbIdLine) {
  $dbId = $dbIdLine.Matches[0].Groups[1].Value
  Write-Host "Detected database_id: $dbId"
  $wranglerPath = Join-Path $PSScriptRoot "..\\wrangler.toml"
  (Get-Content $wranglerPath) `
    -replace 'database_id\s*=\s*"[^"]+"', "database_id = `"$dbId`"" `
    | Set-Content $wranglerPath
  Write-Host "Updated wrangler.toml with D1 database_id."
} else {
  Write-Warning "Could not detect database_id automatically. Update wrangler.toml manually."
}

if ($ApplyRoute) {
  $wranglerPath = Join-Path $PSScriptRoot "..\\wrangler.toml"
  $content = Get-Content $wranglerPath -Raw
  if ($content -notmatch 'routes\s*=\s*\[') {
    $routeBlock = @"
routes = [
  { pattern = "$CustomDomain", custom_domain = true }
]

"@
    if ($content -match 'workers_dev\s*=\s*(true|false)\s*') {
      $updated = [regex]::Replace($content, 'workers_dev\s*=\s*(true|false)\s*', { param($m) "$($m.Value)`r`n`r`n$routeBlock" }, 1)
      Set-Content $wranglerPath $updated
    } else {
      Set-Content $wranglerPath ($routeBlock + $content)
    }
    Write-Host "Added custom domain route for $CustomDomain."
  } else {
    Write-Host "routes block already exists; skipped automatic route patch."
  }
}

Write-Host "Applying remote migrations..."
npm run db:migrate:remote

Write-Host "Deploying worker..."
npm run deploy

Write-Host "Bootstrap complete."
