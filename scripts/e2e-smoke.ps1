param(
  [string]$BaseUrl = "https://users.pajamadot.com",
  [string]$Password = "Passw0rd123!"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$email = "smoke-$stamp@pajamadot.com"
$email2 = "smoke-member-$stamp@pajamadot.com"

function Get-TotpCode {
  param([string]$SecretBase32)

  $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  $normalized = ($SecretBase32.ToUpper() -replace "[^A-Z2-7]", "")
  $bitBuffer = [int64]0
  $bitCount = 0
  $secretBytes = New-Object System.Collections.Generic.List[byte]
  foreach ($ch in $normalized.ToCharArray()) {
    $idx = $alphabet.IndexOf($ch)
    if ($idx -lt 0) { continue }
    $bitBuffer = (($bitBuffer -shl 5) -bor $idx)
    $bitCount += 5
    while ($bitCount -ge 8) {
      $shift = $bitCount - 8
      $byteValue = ($bitBuffer -shr $shift) -band 0xFF
      $secretBytes.Add([byte]$byteValue)
      $bitCount -= 8
      if ($bitCount -gt 0) {
        $mask = ([int64]1 -shl $bitCount) - 1
        $bitBuffer = $bitBuffer -band $mask
      } else {
        $bitBuffer = 0
      }
    }
  }

  $counter = [int64]([System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)
  $counterBytes = New-Object byte[] 8
  for ($i = 7; $i -ge 0; $i--) {
    $counterBytes[$i] = [byte]($counter -band 0xFF)
    $counter = [int64]([math]::Floor($counter / 256))
  }

  $hmac = New-Object System.Security.Cryptography.HMACSHA1(,$secretBytes.ToArray())
  try {
    $hash = $hmac.ComputeHash($counterBytes)
  } finally {
    $hmac.Dispose()
  }

  $offset = $hash[$hash.Length - 1] -band 0x0F
  $binary = (([int]($hash[$offset] -band 0x7F)) -shl 24) `
    -bor (([int]($hash[$offset + 1] -band 0xFF)) -shl 16) `
    -bor (([int]($hash[$offset + 2] -band 0xFF)) -shl 8) `
    -bor ([int]($hash[$offset + 3] -band 0xFF))
  $otp = $binary % 1000000
  return $otp.ToString("D6")
}

Write-Host "Running health check against $BaseUrl"
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/healthz"
if (-not $health.ok) {
  throw "Health check failed"
}

Write-Host "Loading hosted enterprise console"
$enterpriseHosted = Invoke-WebRequest -Method Get -Uri "$BaseUrl/hosted/enterprise"
if ($enterpriseHosted.StatusCode -ne 200 -or -not ($enterpriseHosted.Content -match "Enterprise Console")) {
  throw "Hosted enterprise console is unavailable"
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

Write-Host "Starting MFA TOTP setup"
$mfaSetup = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/mfa/totp/setup/start" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body "{}"
if (-not $mfaSetup.factorId -or -not $mfaSetup.secretBase32) {
  throw "MFA setup start failed"
}

Write-Host "Confirming MFA TOTP setup"
$mfaCode = Get-TotpCode -SecretBase32 $mfaSetup.secretBase32
$mfaConfirm = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/mfa/totp/setup/confirm" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  factorId = $mfaSetup.factorId
  code = $mfaCode
} | ConvertTo-Json -Compress)
if (-not $mfaConfirm.mfa.enabled -or -not $mfaConfirm.recoveryCodes -or $mfaConfirm.recoveryCodes.Count -lt 1) {
  throw "MFA setup confirm failed"
}
$recoveryCode = $mfaConfirm.recoveryCodes[0]

Write-Host "Signing in with password to trigger MFA challenge"
$mfaSignInStart = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/sign-in" -ContentType "application/json" -Body (@{
  email = $email
  password = $Password
} | ConvertTo-Json -Compress)
if (-not $mfaSignInStart.mfaRequired -or -not $mfaSignInStart.challengeId) {
  throw "Expected mfaRequired challenge from sign-in"
}

Write-Host "Completing MFA challenge with TOTP"
$mfaChallengeCode = Get-TotpCode -SecretBase32 $mfaSetup.secretBase32
$mfaSignInFinish = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/mfa/challenge/verify" -ContentType "application/json" -Body (@{
  challengeId = $mfaSignInStart.challengeId
  method = "totp"
  code = $mfaChallengeCode
} | ConvertTo-Json -Compress)
if (-not $mfaSignInFinish.session.accessToken) {
  throw "MFA challenge verify failed for TOTP"
}
$token = $mfaSignInFinish.session.accessToken

Write-Host "Validating recovery code MFA path"
$mfaSignInStartRecovery = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/sign-in" -ContentType "application/json" -Body (@{
  email = $email
  password = $Password
} | ConvertTo-Json -Compress)
if (-not $mfaSignInStartRecovery.mfaRequired -or -not $mfaSignInStartRecovery.challengeId) {
  throw "Expected second mfaRequired challenge from sign-in"
}
$mfaRecoveryFinish = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/mfa/challenge/verify" -ContentType "application/json" -Body (@{
  challengeId = $mfaSignInStartRecovery.challengeId
  method = "recovery_code"
  code = $recoveryCode
} | ConvertTo-Json -Compress)
if (-not $mfaRecoveryFinish.session.accessToken) {
  throw "MFA challenge verify failed for recovery code"
}
$token = $mfaRecoveryFinish.session.accessToken

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

Write-Host "Creating SCIM token"
$scimToken = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/scim/tokens" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke SCIM Token $stamp"
} | ConvertTo-Json -Compress)
if (-not $scimToken.secret) {
  throw "SCIM token secret not returned"
}
$scimSecret = $scimToken.secret

Write-Host "Checking SCIM service provider config"
$scimConfig = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/scim/v2/ServiceProviderConfig" -Headers @{ Authorization = "Bearer $scimSecret" }
if (-not $scimConfig.patch.supported) {
  throw "SCIM service provider config invalid"
}

Write-Host "Provisioning SCIM user"
$scimUserEmail = "scim-$stamp@pajamadot.com"
$scimUser = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/scim/v2/Users" -Headers @{ Authorization = "Bearer $scimSecret" } -ContentType "application/json" -Body (@{
  userName = $scimUserEmail
  displayName = "SCIM Smoke User"
  active = $true
} | ConvertTo-Json -Compress)
if ($scimUser.userName -ne $scimUserEmail) {
  throw "SCIM user provisioning failed"
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
if (-not $orgMembers.members -or $orgMembers.members.Count -lt 3) {
  throw "Expected at least three organization members after SCIM provisioning"
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

Write-Host "Creating SAML connection"
$samlCertBody = "MIICSMOKETESTCERT$stamp"
$samlCertPem = "-----BEGIN CERTIFICATE-----`n$samlCertBody`n-----END CERTIFICATE-----"
$samlConnectionCreate = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/saml/connections" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  name = "Smoke SAML $stamp"
  slug = "smoke-saml-$stamp"
  idpEntityId = "https://idp.smoke.$stamp.example.com/metadata"
  ssoUrl = "https://idp.smoke.$stamp.example.com/sso"
  x509CertPem = $samlCertPem
  requireSignedAssertions = $true
  allowIdpInitiated = $true
} | ConvertTo-Json -Compress)
$samlConnection = $samlConnectionCreate.connection
if (-not $samlConnection.id -or -not $samlConnection.slug) {
  throw "SAML connection creation failed"
}

Write-Host "Listing SAML connections"
$samlConnections = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/saml/connections" -Headers @{ Authorization = "Bearer $token" }
if (-not $samlConnections.connections -or $samlConnections.connections.Count -lt 1) {
  throw "No SAML connections returned"
}

$samlDomain = "corp-$stamp.pajamadot.com"
Write-Host "Creating domain route for SAML"
$domainRoute = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/domain-routes" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  domain = $samlDomain
  connectionType = "saml"
  connectionId = $samlConnection.id
} | ConvertTo-Json -Compress)
if (-not $domainRoute.route.id) {
  throw "Domain route creation failed"
}

Write-Host "Discovering SSO strategy by email domain"
$discovery = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/saml/discover?email=saml-user@$samlDomain"
if ($discovery.strategy -ne "saml") {
  throw "Expected SAML strategy for routed domain"
}

Write-Host "Fetching SAML metadata"
$metadataResponse = Invoke-WebRequest -Method Get -Uri "$BaseUrl/v1/saml/$($samlConnection.slug)/metadata"
if ($metadataResponse.StatusCode -ne 200 -or -not ($metadataResponse.Content -match "EntityDescriptor")) {
  throw "SAML metadata endpoint failed"
}

Write-Host "Starting SAML flow"
$samlStart = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/saml/$($samlConnection.slug)/start?mode=json"
if (-not $samlStart.relayState) {
  throw "SAML start did not return relay state"
}

$samlUserEmail = "saml-$stamp@$samlDomain"
$notBefore = (Get-Date).ToUniversalTime().AddMinutes(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
$notOnOrAfter = (Get-Date).ToUniversalTime().AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ")
$samlResponseXml = @"
<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"" Destination=""$($samlConnection.acsUrl)"" InResponseTo=""$($samlStart.relayState)"">
  <saml:Issuer>$($samlConnection.idpEntityId)</saml:Issuer>
  <ds:Signature>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>$samlCertBody</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml:Assertion>
    <saml:Issuer>$($samlConnection.idpEntityId)</saml:Issuer>
    <saml:Subject>
      <saml:NameID>$samlUserEmail</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData InResponseTo=""$($samlStart.relayState)"" NotOnOrAfter=""$notOnOrAfter"" Recipient=""$($samlConnection.acsUrl)"" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=""$notBefore"" NotOnOrAfter=""$notOnOrAfter"">
      <saml:AudienceRestriction>
        <saml:Audience>$($samlConnection.spEntityId)</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name=""email"">
        <saml:AttributeValue>$samlUserEmail</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=""name"">
        <saml:AttributeValue>SAML Smoke User</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"@
$samlResponseB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($samlResponseXml))

Write-Host "Completing SAML ACS"
$samlAcs = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/saml/$($samlConnection.slug)/acs" -ContentType "application/json" -Body (@{
  SAMLResponse = $samlResponseB64
  RelayState = $samlStart.relayState
} | ConvertTo-Json -Compress)
if (-not $samlAcs.session.accessToken -or $samlAcs.user.email -ne $samlUserEmail) {
  throw "SAML ACS sign-in failed"
}

Write-Host "Setting compliance retention policies"
$retention = Invoke-RestMethod -Method Put -Uri "$BaseUrl/v1/orgs/$orgId/compliance/retention" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  policies = @(
    @{ targetType = "audit_logs"; retentionDays = 30 },
    @{ targetType = "export_jobs"; retentionDays = 14 },
    @{ targetType = "saml_auth_states"; retentionDays = 7 }
  )
} | ConvertTo-Json -Compress -Depth 6)
if (-not $retention.retentionPolicies -or $retention.retentionPolicies.Count -lt 3) {
  throw "Retention policy update failed"
}

Write-Host "Running compliance prune dry-run"
$prune = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/compliance/prune" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  dryRun = $true
} | ConvertTo-Json -Compress)
if (-not $prune.affected) {
  throw "Compliance prune endpoint failed"
}

Write-Host "Creating organization KMS key"
$kmsKeyCreate = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/kms/keys" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  alias = "smoke-key-$stamp"
} | ConvertTo-Json -Compress)
$kmsKey = $kmsKeyCreate.key
if (-not $kmsKey.id) {
  throw "KMS key creation failed"
}

Write-Host "Validating KMS encrypt/decrypt"
$kmsEncrypt = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/kms/keys/$($kmsKey.id)/encrypt" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  plaintext = "smoke-secret-$stamp"
} | ConvertTo-Json -Compress)
if (-not $kmsEncrypt.ciphertext) {
  throw "KMS encrypt failed"
}
$kmsDecrypt = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/kms/keys/$($kmsKey.id)/decrypt" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  ciphertext = $kmsEncrypt.ciphertext
} | ConvertTo-Json -Compress)
if ($kmsDecrypt.plaintext -ne "smoke-secret-$stamp") {
  throw "KMS decrypt failed"
}

Write-Host "Creating encrypted compliance export job"
$exportJobCreate = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/orgs/$orgId/compliance/exports" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body (@{
  targetType = "all"
  kmsKeyId = $kmsKey.id
  filters = @{ auditLogLimit = 200 }
} | ConvertTo-Json -Compress -Depth 6)
if (-not $exportJobCreate.job.id) {
  throw "Export job creation failed"
}

Write-Host "Reading compliance export result"
$exportJob = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/compliance/exports/$($exportJobCreate.job.id)?includeResult=true" -Headers @{ Authorization = "Bearer $token" }
if ($exportJob.job.status -ne "completed" -or -not $exportJob.job.resultEncrypted -or -not $exportJob.result.ciphertext) {
  throw "Export job did not complete with encrypted payload"
}

Write-Host "Reading enterprise diagnostics"
$enterpriseDiag = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/orgs/$orgId/enterprise/diagnostics" -Headers @{ Authorization = "Bearer $token" }
if (-not $enterpriseDiag.diagnostics -or $enterpriseDiag.diagnostics.samlConnections.total -lt 1) {
  throw "Enterprise diagnostics endpoint failed"
}

Write-Host "Smoke test succeeded for $email"
