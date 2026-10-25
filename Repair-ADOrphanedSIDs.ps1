
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
  Audit orphaned domain-account SIDs in Active Directory ACLs.

.DESCRIPTION
  Default behavior is audit-only.
  -Remove removes unresolved S-1-5-21 domain-account SIDs from
  explicit ACEs. Inherited ACEs are audited but not directly removed.
  Use -WhatIf to preview writes.

.EXAMPLES
  .\Repair-ADOrphanedSIDs.ps1
  .\Repair-ADOrphanedSIDs.ps1 -SearchBase "OU=Servers,DC=lab,DC=local"
  .\Repair-ADOrphanedSIDs.ps1 -Remove -WhatIf
  .\Repair-ADOrphanedSIDs.ps1 -Remove
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SearchBase,
    [string]$ReportPath = ".\AD-Orphaned-SID-Audit.csv",
    [switch]$Remove
)

Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain -ErrorAction Stop

if (-not $SearchBase) {
    $SearchBase = $domain.DistinguishedName
}

$report = [System.Collections.Generic.List[object]]::new()

Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Search base: $SearchBase"
Write-Host "Removal enabled: $Remove"

# Cache SID translation results to reduce repeated lookups.
$sidCache = @{}

function Test-OrphanedDomainSid {
    param([System.Security.Principal.SecurityIdentifier]$Sid)

    $sidText = $Sid.Value

    # Limit scope to ordinary domain account/group SIDs.
    # Do not automatically classify well-known SIDs as orphaned.
    if ($sidText -notmatch '^S-1-5-21-(\d+-){2}\d+-\d+$') {
        return $false
    }

    if ($sidCache.ContainsKey($sidText)) {
        return $sidCache[$sidText]
    }

    try {
        $null = $Sid.Translate(
            [System.Security.Principal.NTAccount]
        )
        $sidCache[$sidText] = $false
    }
    catch {
        # Translation failure is a candidate, not absolute proof.
        $sidCache[$sidText] = $true
    }

    return $sidCache[$sidText]
}

$objects = Get-ADObject `
    -SearchBase $SearchBase `
    -SearchScope Subtree `
    -LDAPFilter "(objectClass=*)" `
    -Properties objectSid `
    -ResultSetSize $null `
    -ErrorAction Stop

$total = @($objects).Count
$index = 0

foreach ($obj in $objects) {
    $index++

    Write-Progress `
        -Activity "Auditing Active Directory ACLs" `
        -Status "$index of $total : $($obj.DistinguishedName)" `
        -PercentComplete (($index / [math]::Max($total, 1)) * 100)

    $path = "AD:\$($obj.DistinguishedName)"

    try {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    }
    catch {
        $report.Add([pscustomobject]@{
            ObjectDN        = $obj.DistinguishedName
            SID             = ""
            Rights          = ""
            AccessType      = ""
            IsInherited     = ""
            Status          = "ACL_READ_FAILED: $($_.Exception.Message)"
        })
        continue
    }

    # Snapshot the rules before modifying the ACL.
    $rules = @(
        $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
    )

    $orphanRules = @(
        $rules | Where-Object {
            $_.IdentityReference -is
                [System.Security.Principal.SecurityIdentifier] -and
            (Test-OrphanedDomainSid -Sid $_.IdentityReference)
        }
    )

    foreach ($rule in $orphanRules) {
        $sidText = $rule.IdentityReference.Value
        $status = if ($rule.IsInherited) {
            "INHERITED_REVIEW_SOURCE_ACL"
        } else {
            "ORPHAN_EXPLICIT_FOUND"
        }

        if ($Remove -and -not $rule.IsInherited) {
            if ($PSCmdlet.ShouldProcess(
                "$($obj.DistinguishedName) [$sidText]",
                "Remove explicit orphaned SID ACE"
            )) {
                try {
                    $acl.RemoveAccessRuleSpecific($rule)
                    Set-Acl -LiteralPath $path -AclObject $acl `
                        -ErrorAction Stop

                    $status = "REMOVED_EXPLICIT_ACE"

                    # Re-read the ACL for each further rule on this object.
                    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                }
                catch {
                    $status = "REMOVE_FAILED: $($_.Exception.Message)"
                }
            }
            elseif ($WhatIfPreference) {
                $status = "WHATIF_PREVIEW"
            }
        }

        $report.Add([pscustomobject]@{
            ObjectDN    = $obj.DistinguishedName
            SID         = $sidText
            Rights      = $rule.ActiveDirectoryRights.ToString()
            AccessType  = $rule.AccessControlType.ToString()
            IsInherited = $rule.IsInherited
            Status      = $status
        })
    }
}

Write-Progress -Activity "Auditing Active Directory ACLs" -Completed

$report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host "`nAudit complete." -ForegroundColor Green
Write-Host "Objects scanned: $total"
Write-Host "Findings: $($report.Count)"
Write-Host "Report: $((Resolve-Path $ReportPath -ErrorAction SilentlyContinue).Path)"

$report | Group-Object Status |
    Select-Object Name, Count |
    Format-Table -AutoSize
