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

Write-Host "Reading session risk events"
$riskEvents = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/auth/sessions/risk-events" -Headers @{ Authorization = "Bearer $token" }
if (-not $riskEvents.riskEvents -or $riskEvents.riskEvents.Count -lt 1) {
  throw "Expected at least one risk event"
}

Write-Host "Creating personal API key"
$personalKey = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/api-keys" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke Personal Key $stamp"
  scopes = @("m2m:read")
} | ConvertTo-Json -Compress)
if (-not $personalKey.secret) {
  throw "Personal API key secret not returned"
}

Write-Host "Verifying personal API key via m2m endpoint"
$m2mPersonal = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/m2m/me" -Headers @{ "x-api-key" = $personalKey.secret }
if ($m2mPersonal.principalType -ne "user") {
  throw "Expected user principal for personal API key"
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

Write-Host "Creating organization webhook endpoint"
$webhook = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/webhooks" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  url = "https://httpbin.org/post"
  eventTypes = @("org.webhook.test")
} | ConvertTo-Json -Compress)
if (-not $webhook.webhook.id -or -not $webhook.signingSecret) {
  throw "Webhook creation failed"
}
$webhookId = $webhook.webhook.id

Write-Host "Listing organization webhooks"
$webhooks = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/webhooks" -Headers @{ Authorization = "Bearer $token" }
if (-not $webhooks.webhooks -or $webhooks.webhooks.Count -lt 1) {
  throw "No webhooks returned"
}

Write-Host "Creating fine-grained policy rule"
$policy = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/policies" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  subjectType = "role"
  subjectId = "admin"
  resource = "webhooks"
  action = "manage"
  effect = "allow"
} | ConvertTo-Json -Compress)
if (-not $policy.policy.id) {
  throw "Policy creation failed"
}

Write-Host "Listing organization policies"
$policies = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/policies" -Headers @{ Authorization = "Bearer $token" }
if (-not $policies.policies -or $policies.policies.Count -lt 1) {
  throw "No organization policies returned"
}

Write-Host "Sending webhook test event"
$webhookTest = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/webhooks/$webhookId/test" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body "{}"
if (-not $webhookTest.ok) {
  throw "Webhook test trigger failed"
}

Write-Host "Listing webhook deliveries"
$deliveries = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/webhooks/$webhookId/deliveries" -Headers @{ Authorization = "Bearer $token" }
if (-not $deliveries.deliveries -or $deliveries.deliveries.Count -lt 1) {
  throw "No webhook deliveries returned"
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

Write-Host "Creating service account"
$serviceAccount = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/service-accounts" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke Service Account $stamp"
  description = "Smoke test machine identity"
} | ConvertTo-Json -Compress)
if (-not $serviceAccount.serviceAccount.id) {
  throw "Service account creation failed"
}
$serviceAccountId = $serviceAccount.serviceAccount.id

Write-Host "Creating service account API key"
$serviceKey = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/service-accounts/$serviceAccountId/api-keys" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke SA Key $stamp"
  scopes = @("m2m:read", "org:read")
} | ConvertTo-Json -Compress)
if (-not $serviceKey.secret) {
  throw "Service account API key secret not returned"
}

Write-Host "Verifying service account API key via m2m endpoint"
$m2mService = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/m2m/me" -Headers @{ "x-api-key" = $serviceKey.secret }
if ($m2mService.principalType -ne "service_account") {
  throw "Expected service_account principal for service account API key"
}
if ($m2mService.serviceAccount.id -ne $serviceAccountId) {
  throw "Unexpected service account id from m2m endpoint"
}

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

Write-Host "Creating scoped auth project"
$project = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/projects" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke Project $stamp"
  slug = "smoke-project-$stamp"
  authDomain = "tenant-$stamp.users.pajamadot.com"
  branding = @{
    accentColor = "#0f766e"
  }
} | ConvertTo-Json -Compress -Depth 5)
if (-not $project.project.id) {
  throw "Project creation failed"
}
$projectId = $project.project.id

Write-Host "Listing projects"
$projects = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/projects" -Headers @{ Authorization = "Bearer $token" }
if (-not $projects.projects -or $projects.projects.Count -lt 1) {
  throw "No projects returned"
}

Write-Host "Configuring project scoped Google provider"
$projectGoogle = Invoke-RestMethod -Method Put -Uri "$BaseUrl/v1/projects/$projectId/oauth/providers/google" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  enabled = $true
  clientId = "smoke-client-id-$stamp"
  clientSecret = "smoke-client-secret-$stamp-123456"
  redirectUri = "https://tenant-$stamp.users.pajamadot.com/v1/oauth/google/callback"
  scope = "openid email profile"
} | ConvertTo-Json -Compress)
if (-not $projectGoogle.enabled) {
  throw "Project scoped Google provider update failed"
}

Write-Host "Smoke test succeeded for $email"
