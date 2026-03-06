#
.SYNOPSIS
    This PowerShell script ensures the Windows 10 account lockout threshold is configured
    to lock out accounts after no more than 3 invalid logon attempts, reducing the risk
    of brute-force attacks.
.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AC-000035.ps1
#>

# Export current security policy to a temp file
$tempCfg = "$env:TEMP\secpol_export.cfg"
secedit /export /cfg $tempCfg /quiet

# Read the exported policy
$policyContent = Get-Content $tempCfg

# Find the current lockout threshold value
$lockoutLine = $policyContent | Where-Object { $_ -match "LockoutBadCount" }
Write-Host "[INFO] Current policy line: $lockoutLine"

# Parse the value (0 means disabled/never lockout)
$currentValue = 0
if ($lockoutLine -match "=\s*(\d+)") {
    $currentValue = [int]$Matches[1]
}

$maxAllowed = 3

if ($currentValue -ge 1 -and $currentValue -le $maxAllowed) {
    Write-Host "[PASS] Account lockout threshold is set to '$currentValue'. STIG WN10-AC-000035 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Account lockout threshold is '$currentValue'. Setting to '$maxAllowed'..." -ForegroundColor Yellow

    # Build a new config file to apply the setting
    $newCfg = "$env:TEMP\secpol_apply.cfg"
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
LockoutBadCount = $maxAllowed
"@ | Out-File -FilePath $newCfg -Encoding Unicode

    # Apply the new policy
    secedit /configure /db secedit.sdb /cfg $newCfg /areas SECURITYPOLICY /quiet

    Write-Host "[SUCCESS] Account lockout threshold set to '$maxAllowed'. STIG WN10-AC-000035 is now satisfied." -ForegroundColor Green
}

# Cleanup temp files
Remove-Item $tempCfg -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol_apply.cfg" -ErrorAction SilentlyContinue
