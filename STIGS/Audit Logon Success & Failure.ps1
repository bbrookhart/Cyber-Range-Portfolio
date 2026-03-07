#
.SYNOPSIS
    This PowerShell script ensures the Windows 11 Advanced Audit Policy is configured
    to audit Success and Failure for Logon, Logoff, and Account Lockout events, providing
    full visibility into authentication activity required to detect lateral movement,
    credential attacks, and unauthorized access.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000030
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-AU-000030.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

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
# Subcategories required for WN11-AU-000030
# ------------------------------------------------------------------
$requiredSubcategories = @(
    "Logon",
    "Logoff",
    "Account Lockout"
)

$allCompliant = $true

Write-Host ""
Write-Host "[INFO] --- Checking Advanced Audit Policy Subcategories ---" -ForegroundColor Cyan

foreach ($subcategory in $requiredSubcategories) {
    $currentSetting = Get-AuditSetting -Subcategory $subcategory
    Write-Host "[INFO] '$subcategory' current setting: $currentSetting"

    if ($currentSetting -eq "Success and Failure") {
        Write-Host "[PASS] '$subcategory' is correctly set to 'Success and Failure'." -ForegroundColor Green
    } else {
        $allCompliant = $false
        Write-Host "[REMEDIATE] '$subcategory' is '$currentSetting'. Applying 'Success and Failure'..." -ForegroundColor Yellow

        $result = auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable 2>&1

        if ($LASTEXITCODE -eq 0) {
            $verified = Get-AuditSetting -Subcategory $subcategory
            if ($verified -eq "Success and Failure") {
                Write-Host "[SUCCESS] '$subcategory' successfully set to 'Success and Failure'." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] '$subcategory' verification failed. Post-remediation value: '$verified'." -ForegroundColor Red
                $allCompliant = $false
            }
        } else {
            Write-Host "[ERROR] auditpol command failed for '$subcategory': $result" -ForegroundColor Red
            $allCompliant = $false
        }
    }
    Write-Host ""
}

# ------------------------------------------------------------------
# Ensure Advanced Audit Policy takes precedence over legacy settings
# (SCENoApplyLegacyAuditPolicy must = 1 on Windows 11)
# ------------------------------------------------------------------
Write-Host "[INFO] --- Verifying SCENoApplyLegacyAuditPolicy ---" -ForegroundColor Cyan
$lsaPath         = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$legacyOverride  = (Get-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy

Write-Host "[INFO] Current SCENoApplyLegacyAuditPolicy: $legacyOverride (required: 1)"

if ($legacyOverride -eq 1) {
    Write-Host "[PASS] SCENoApplyLegacyAuditPolicy is already set to 1. Advanced audit policy takes precedence." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Setting SCENoApplyLegacyAuditPolicy to 1..." -ForegroundColor Yellow
    Set-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
    $newLegacyVal = (Get-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
    if ($newLegacyVal -eq 1) {
        Write-Host "[SUCCESS] SCENoApplyLegacyAuditPolicy set to 1. Advanced audit policy will now take precedence on Windows 11." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to set SCENoApplyLegacyAuditPolicy. Current value: $newLegacyVal." -ForegroundColor Red
    }
}

# ------------------------------------------------------------------
# Final compliance summary
# ------------------------------------------------------------------
Write-Host ""
if ($allCompliant) {
    Write-Host "[PASS] All logon audit subcategories are configured correctly. STIG WN11-AU-000030 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[WARN] One or more audit subcategory remediations may need review. Please verify output above." -ForegroundColor Yellow
}
