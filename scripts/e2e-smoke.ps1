param(
  [string]$BaseUrl = "https://users.pajamadot.com",
  [string]$Password = "Passw0rd123!"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$email = "smoke-$stamp@pajamadot.com"

Write-Host "Running health check against $BaseUrl"
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/healthz"
if (-not $health.ok) {
  throw "Health check failed"
}

Write-Host "Creating smoke user: $email"
$signup = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/sign-up" -ContentType "application/json" -Body (@{
  email = $email
  password = $Password
  fullName = "Smoke User"
} | ConvertTo-Json -Compress)

$token = $signup.session.accessToken
if (-not $token) {
  throw "No access token from sign-up"
}

Write-Host "Fetching current user"
$me = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/auth/me" -Headers @{ Authorization = "Bearer $token" }
if ($me.user.email -ne $email) {
  throw "Unexpected /me email"
}

Write-Host "Listing sessions"
$sessions = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/auth/sessions" -Headers @{ Authorization = "Bearer $token" }
if (-not $sessions.sessions -or $sessions.sessions.Count -lt 1) {
  throw "No active sessions returned"
}

Write-Host "Smoke test succeeded for $email"
