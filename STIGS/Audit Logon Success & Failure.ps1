#
.SYNOPSIS
    This PowerShell script ensures Advanced Audit Policy is configured to audit both
    Success and Failure logon events on Windows 10, providing visibility into
    authentication activity critical for detecting lateral movement and brute-force attacks.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000030
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AU-000030.ps1
#>

# ------------------------------------------------------------------
# Helper: Parse auditpol output for a given subcategory
# ------------------------------------------------------------------
function Get-AuditSetting {
    param ([string]$Subcategory)

    $output = auditpol /get /subcategory:"$Subcategory" 2>&1
    $line   = $output | Where-Object { $_ -match $Subcategory }

    if ($line -match "Success and Failure") { return "Success and Failure" }
    elseif ($line -match "Success")         { return "Success" }
    elseif ($line -match "Failure")         { return "Failure" }
    else                                    { return "No Auditing" }
}

# ------------------------------------------------------------------
# Define required subcategories for Logon auditing (WN10-AU-000030)
# ------------------------------------------------------------------
$requiredSubcategories = @(
    "Logon",
    "Logoff",
    "Account Lockout"
)

$allCompliant = $true

foreach ($subcategory in $requiredSubcategories) {
    $currentSetting = Get-AuditSetting -Subcategory $subcategory
    Write-Host "[INFO] Current audit setting for '$subcategory': $currentSetting"

    if ($currentSetting -eq "Success and Failure") {
        Write-Host "[PASS] '$subcategory' is already set to 'Success and Failure'." -ForegroundColor Green
    } else {
        $allCompliant = $false
        Write-Host "[REMEDIATE] Setting '$subcategory' to 'Success and Failure'..." -ForegroundColor Yellow

        # Apply via auditpol
        $result = auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable 2>&1

        if ($LASTEXITCODE -eq 0) {
            $verified = Get-AuditSetting -Subcategory $subcategory
            if ($verified -eq "Success and Failure") {
                Write-Host "[SUCCESS] '$subcategory' audit policy set to 'Success and Failure'." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] Failed to verify '$subcategory' after applying. Current value: $verified" -ForegroundColor Red
                $allCompliant = $false
            }
        } else {
            Write-Host "[ERROR] auditpol command failed for '$subcategory': $result" -ForegroundColor Red
            $allCompliant = $false
        }
    }
}

# ------------------------------------------------------------------
# Final compliance summary
# ------------------------------------------------------------------
Write-Host ""
if ($allCompliant) {
    Write-Host "[PASS] All logon audit subcategories are configured correctly. STIG WN10-AU-000030 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[WARN] One or more audit subcategories may not have applied correctly. Please review output above." -ForegroundColor Yellow
}

# ------------------------------------------------------------------
# Confirm SCE override is not blocking advanced audit policy
# ------------------------------------------------------------------
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$scenoOverride = (Get-ItemProperty -Path $registryPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy

if ($scenoOverride -ne 1) {
    Write-Host "[INFO] SCENoApplyLegacyAuditPolicy is not set to 1. Applying to ensure advanced audit policy takes precedence..." -ForegroundColor Cyan
    Set-ItemProperty -Path $registryPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
    Write-Host "[SUCCESS] SCENoApplyLegacyAuditPolicy set to 1. Advanced audit policy will now take precedence." -ForegroundColor Green
} else {
    Write-Host "[PASS] SCENoApplyLegacyAuditPolicy is already set to 1." -ForegroundColor Green
}
