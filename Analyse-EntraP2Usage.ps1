<#
.SYNOPSIS
  Analyse Entra ID P2 licensing vs P2 feature usage.

.DESCRIPTION
  - Connects to Microsoft Graph
  - Pulls all users & their assigned licences
  - Identifies users licensed for Entra ID P2 via:
      * Standalone Entra ID P2 (84a661c4-e949-4bd2-a560-ed7766fcaf2b)
      * Microsoft 365 E5 (c7df2760-2c81-4ef7-b578-5b5392b571df)
  - Pulls Conditional Access policies that depend on risk (P2-only feature)
  - Resolves which users are in scope of those policies
  - Optionally pulls Identity Protection risky users
  - Exports CSVs:
      * P2LicensedUsers.csv                – users legitimately covered by P2/E5
      * P2FeatureScopedUsers.csv           – users in scope of P2-only CA policies
      * P2BenefittingNoP2License.csv       – in scope but without P2/E5
      * RiskyUsersNoP2License.csv (opt.)   – Identity Protection risky users without P2/E5

.NOTES
  Requires Microsoft.Graph PowerShell module:
    Install-Module Microsoft.Graph -Scope CurrentUser
#>

param(
    # Output directory for CSV files
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",

    # Include Identity Protection risky user check
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIdentityProtection
)

# =========================
#  Config: SKU IDs
# =========================

# Entra ID P2 standalone
$SkuEntraP2 = [Guid]"84a661c4-e949-4bd2-a560-ed7766fcaf2b"

# Microsoft 365 E5 (includes Entra ID P2 rights)
$SkuM365E5 = [Guid]"c7df2760-2c81-4ef7-b578-5b5392b571df"

$P2EntitledSkus = @($SkuEntraP2, $SkuM365E5)

# =========================
#  Helper: Ensure module
# =========================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Microsoft.Graph module not found. Install with:" -ForegroundColor Yellow
    Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    throw "Microsoft.Graph module is required."
}

Import-Module Microsoft.Graph

# =========================
#  Connect to Graph
# =========================

$scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",              # for CA policies
    "IdentityRiskyUser.Read.All",   # for Identity Protection risky users
    "IdentityRiskEvent.Read.All"    # for Identity Protection events
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes | Out-Null

$ctx = Get-MgContext
Write-Host "Connected as $($ctx.Account) in tenant $($ctx.TenantId)" -ForegroundColor Green

# =========================
#  Helper: Safe Output Path
# =========================

if (-not (Test-Path $OutputPath)) {
    Write-Host "Output path '$OutputPath' does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

function Join-OutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    return (Join-Path -Path $OutputPath -ChildPath $FileName)
}

# =========================
#  Step 1: Get all users
# =========================

Write-Host "Retrieving all users and assigned licences..." -ForegroundColor Cyan

$allUsers = Get-MgUser -All -Property "id,displayName,userPrincipalName,mail,assignedLicenses"

if (-not $allUsers) {
    throw "No users returned. Check permissions / tenant."
}

# Index users by Id for quick lookups later
$usersById = @{}
foreach ($u in $allUsers) {
    $usersById[$u.Id] = $u
}

Write-Host "Total users found: $($allUsers.Count)" -ForegroundColor Green

# =========================
#  Step 2: Identify P2-entitled users
# =========================

Write-Host "Identifying users with Entra ID P2 rights (Standalone P2 or M365 E5)..." -ForegroundColor Cyan

$usersWithP2Rights = $allUsers | Where-Object {
    ($_.AssignedLicenses.SkuId | Where-Object { $P2EntitledSkus -contains $_ }).Count -gt 0
}

$usersWithoutP2Rights = $allUsers | Where-Object {
    ($_.AssignedLicenses.SkuId | Where-Object { $P2EntitledSkus -contains $_ }).Count -eq 0
}

Write-Host "Users with P2/E5 rights: $($usersWithP2Rights.Count)" -ForegroundColor Green

# Export licensed users
$licensedCsv = Join-OutputPath "P2LicensedUsers.csv"
$usersWithP2Rights |
    Select-Object DisplayName, UserPrincipalName, Mail, Id, AssignedLicenses |
    Export-Csv -Path $licensedCsv -NoTypeInformation -Encoding UTF8

Write-Host "Exported P2-licensed users to: $licensedCsv" -ForegroundColor Green

# =========================
#  Step 3: Conditional Access policies using risk
# =========================

Write-Host "Retrieving Conditional Access policies that use risk (P2-only features)..." -ForegroundColor Cyan

$riskPolicies = Get-MgIdentityConditionalAccessPolicy -All | Where-Object {
    ($_.Conditions.SignInRiskLevels -and $_.Conditions.SignInRiskLevels.Count -gt 0) -or
    ($_.Conditions.UserRiskLevels   -and $_.Conditions.UserRiskLevels.Count   -gt 0)
}

Write-Host "Risk-based Conditional Access policies found: $($riskPolicies.Count)" -ForegroundColor Green

if (-not $riskPolicies -or $riskPolicies.Count -eq 0) {
    Write-Host "No risk-based CA policies found. P2 usage may be coming from other features (IP, PIM, etc.)." -ForegroundColor Yellow
}

# =========================
#  Helper: Resolve CA policy users
# =========================

function Get-UsersFromGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue
    if (-not $members) { return @() }

    # Filter to user objects only
    $users = @()
    foreach ($m in $members) {
        if ($m.'@odata.type' -eq "#microsoft.graph.user") {
            # Some objects may not have all properties, so just keep Id
            if ($usersById.ContainsKey($m.Id)) {
                $users += $usersById[$m.Id]
            }
        }
    }
    return $users
}

function Resolve-CaPolicyUsers {
    param(
        [Parameter(Mandatory = $true)]
        $Policy
    )

    $userCondition = $Policy.Conditions.Users

    # If policy targets "All" users, start from full user set,
    # then remove excluded users / groups / roles.
    $initialUserSet = New-Object System.Collections.Generic.HashSet[string]

    $includeAllUsers = $false
    if ($userCondition.IncludeUsers -contains "All") {
        $includeAllUsers = $true
        foreach ($u in $allUsers) {
            $null = $initialUserSet.Add($u.Id)
        }
    }

    # Include specifically listed users
    foreach ($userId in $userCondition.IncludeUsers) {
        if ($userId -and $userId -ne "All" -and $usersById.ContainsKey($userId)) {
            $null = $initialUserSet.Add($userId)
        }
    }

    # Include members of included groups
    foreach ($groupId in $userCondition.IncludeGroups) {
        $groupUsers = Get-UsersFromGroup -GroupId $groupId
        foreach ($gu in $groupUsers) {
            $null = $initialUserSet.Add($gu.Id)
        }
    }

    # TODO: IncludeRoles could be handled here if needed (resolve role assignments)

    # Exclusions
    foreach ($userId in $userCondition.ExcludeUsers) {
        if ($userId -and $usersById.ContainsKey($userId)) {
            $null = $initialUserSet.Remove($userId)
        }
    }

    foreach ($groupId in $userCondition.ExcludeGroups) {
        $groupUsers = Get-UsersFromGroup -GroupId $groupId
        foreach ($gu in $groupUsers) {
            $null = $initialUserSet.Remove($gu.Id)
        }
    }

    # NOTE: ExcludeRoles handling could be added similarly, if required.

    # Return user objects
    $resolvedUsers = @()
    foreach ($id in $initialUserSet) {
        if ($usersById.ContainsKey($id)) {
            $resolvedUsers += $usersById[$id]
        }
    }

    return $resolvedUsers
}

# =========================
#  Step 4: Union of all users in risk-based CA policies
# =========================

$userIdsInRiskPolicies = New-Object System.Collections.Generic.HashSet[string]

foreach ($policy in $riskPolicies) {
    Write-Host "Resolving users for policy '$($policy.DisplayName)'..." -ForegroundColor DarkCyan
    $policyUsers = Resolve-CaPolicyUsers -Policy $policy
    foreach ($u in $policyUsers) {
        $null = $userIdsInRiskPolicies.Add($u.Id)
    }
}

$riskPolicyUsers = $allUsers | Where-Object { $userIdsInRiskPolicies.Contains($_.Id) }

Write-Host "Total users in scope of risk-based CA policies: $($riskPolicyUsers.Count)" -ForegroundColor Green

# Export all P2-feature-scoped users (via CA)
$featureScopedCsv = Join-OutputPath "P2FeatureScopedUsers.csv"
$riskPolicyUsers |
    Select-Object DisplayName, UserPrincipalName, Mail, Id, AssignedLicenses |
    Export-Csv -Path $featureScopedCsv -NoTypeInformation -Encoding UTF8

Write-Host "Exported users in scope of risk-based CA to: $featureScopedCsv" -ForegroundColor Green

# =========================
#  Step 5: Benefitting but not licensed
# =========================

Write-Host "Calculating users benefitting from P2 CA features but without P2/E5 licence..." -ForegroundColor Cyan

$benefittingButUnlicensed =
    $riskPolicyUsers |
    Where-Object {
        ($_.AssignedLicenses.SkuId | Where-Object { $P2EntitledSkus -contains $_ }).Count -eq 0
    }

Write-Host "Users benefitting from P2 CA features without P2/E5: $($benefittingButUnlicensed.Count)" -ForegroundColor Yellow

$benefittingCsv = Join-OutputPath "P2BenefittingNoP2License.csv"
$benefittingButUnlicensed |
    Select-Object DisplayName, UserPrincipalName, Mail, Id |
    Export-Csv -Path $benefittingCsv -NoTypeInformation -Encoding UTF8

Write-Host "Exported benefitting-but-unlicensed users to: $benefittingCsv" -ForegroundColor Green

# =========================
#  Step 6: Identity Protection (optional)
# =========================

if ($IncludeIdentityProtection) {
    Write-Host "Pulling Identity Protection risky users..." -ForegroundColor Cyan

    try {
        $riskyUsers = Get-MgIdentityProtectionRiskyUser -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to retrieve risky users via Identity Protection API. Check IP licensing and permissions."
        $riskyUsers = @()
    }

    if ($riskyUsers -and $riskyUsers.Count -gt 0) {
        $riskyUsersUnlicensed = @()

        foreach ($ru in $riskyUsers) {
            if ($usersById.ContainsKey($ru.Id)) {
                $u = $usersById[$ru.Id]

                $hasP2Rights = ($u.AssignedLicenses.SkuId | Where-Object { $P2EntitledSkus -contains $_ }).Count -gt 0
                if (-not $hasP2Rights) {
                    $riskyUsersUnlicensed += [PSCustomObject]@{
                        DisplayName        = $u.DisplayName
                        UserPrincipalName  = $u.UserPrincipalName
                        Mail               = $u.Mail
                        UserId             = $u.Id
                        RiskLevel          = $ru.RiskLevel
                        RiskState          = $ru.RiskState
                        RiskDetail         = $ru.RiskDetail
                        RiskLastUpdated    = $ru.RiskLastUpdatedDateTime
                    }
                }
            }
        }

        Write-Host "Identity Protection risky users without P2/E5: $($riskyUsersUnlicensed.Count)" -ForegroundColor Yellow

        $riskyCsv = Join-OutputPath "RiskyUsersNoP2License.csv"
        $riskyUsersUnlicensed |
            Export-Csv -Path $riskyCsv -NoTypeInformation -Encoding UTF8

        Write-Host "Exported Identity Protection risky users without P2/E5 to: $riskyCsv" -ForegroundColor Green
    }
    else {
        Write-Host "No risky users returned from Identity Protection API." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Skipping Identity Protection risky-user analysis (use -IncludeIdentityProtection to enable)." -ForegroundColor DarkYellow
}

Write-Host "`nDone. CSV reports are in: $OutputPath" -ForegroundColor Green
