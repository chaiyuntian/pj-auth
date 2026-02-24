param(
  [string]$BaseUrl = "https://users.pajamadot.com",
  [string]$Password = "Passw0rd123!"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$email = "smoke-$stamp@pajamadot.com"
$email2 = "smoke-member-$stamp@pajamadot.com"

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

Write-Host "Creating second smoke user: $email2"
$signup2 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/sign-up" -ContentType "application/json" -Body (@{
  email = $email2
  password = $Password
  fullName = "Smoke Member"
} | ConvertTo-Json -Compress)
$token2 = $signup2.session.accessToken
if (-not $token2) {
  throw "No access token from second sign-up"
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

Write-Host "Creating organization"
$org = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke Organization $stamp"
  slug = "smoke-org-$stamp"
} | ConvertTo-Json -Compress)
if (-not $org.organization.id) {
  throw "Organization creation failed"
}
$orgId = $org.organization.id

Write-Host "Listing organizations"
$orgs = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs" -Headers @{ Authorization = "Bearer $token" }
if (-not $orgs.organizations -or $orgs.organizations.Count -lt 1) {
  throw "No organizations returned"
}

Write-Host "Adding second user to organization"
$addMember = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/members" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  email = $email2
  role = "member"
} | ConvertTo-Json -Compress)
if ($addMember.user.email -ne $email2) {
  throw "Second user was not added to organization"
}

Write-Host "Verifying organization members"
$orgMembers = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/members" -Headers @{ Authorization = "Bearer $token" }
if (-not $orgMembers.members -or $orgMembers.members.Count -lt 2) {
  throw "Expected at least two organization members"
}

Write-Host "Creating team"
$team = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/teams" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke Team $stamp"
  slug = "smoke-team-$stamp"
} | ConvertTo-Json -Compress)
if (-not $team.team.id) {
  throw "Team creation failed"
}
$teamId = $team.team.id

Write-Host "Adding second user to team"
$addTeamMember = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/teams/$teamId/members" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  email = $email2
  role = "member"
} | ConvertTo-Json -Compress)
if ($addTeamMember.user.email -ne $email2) {
  throw "Second user was not added to team"
}

Write-Host "Listing team members"
$teamMembers = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/teams/$teamId/members" -Headers @{ Authorization = "Bearer $token" }
if (-not $teamMembers.members -or $teamMembers.members.Count -lt 2) {
  throw "Expected at least two team members"
}

Write-Host "Verifying second user can see org membership"
$memberOrgs = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs" -Headers @{ Authorization = "Bearer $token2" }
if (-not $memberOrgs.organizations -or $memberOrgs.organizations.Count -lt 1) {
  throw "Second user cannot see organization membership"
}

Write-Host "Smoke test succeeded for $email"
