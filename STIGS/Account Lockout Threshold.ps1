#
.SYNOPSIS
    This PowerShell script ensures the Windows 11 account lockout threshold is configured
    to lock out accounts after no more than 3 invalid logon attempts, reducing the risk
    of brute-force and password-spray attacks.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000035
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-AC-000035.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Export current security policy to a temp file
$tempCfg = "$env:TEMP\secpol_export_wn11.cfg"
secedit /export /cfg $tempCfg /quiet

if (-not (Test-Path $tempCfg)) {
    Write-Host "[ERROR] Failed to export security policy. Ensure the script is run as Administrator." -ForegroundColor Red
    exit 1
}

# Read the exported policy
$policyContent = Get-Content $tempCfg

# Find the current lockout threshold line
$lockoutLine = $policyContent | Where-Object { $_ -match "LockoutBadCount" }
Write-Host "[INFO] Current policy line: $lockoutLine"

# Parse the value (0 = lockout disabled)
$currentValue = 0
if ($lockoutLine -match "=\s*(\d+)") {
    $currentValue = [int]$Matches[1]
}

$maxAllowed = 3

if ($currentValue -ge 1 -and $currentValue -le $maxAllowed) {
    Write-Host "[PASS] Account lockout threshold is set to '$currentValue' (required: 1-$maxAllowed). STIG WN11-AC-000035 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Account lockout threshold is '$currentValue'. Setting to '$maxAllowed'..." -ForegroundColor Yellow

    # Build a remediation config
    $newCfg = "$env:TEMP\secpol_apply_wn11.cfg"
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
LockoutBadCount = $maxAllowed
"@ | Out-File -FilePath $newCfg -Encoding Unicode

    # Apply via secedit
    secedit /configure /db secedit.sdb /cfg $newCfg /areas SECURITYPOLICY /quiet

    # Verify by re-exporting
    $verifyCfg = "$env:TEMP\secpol_verify_wn11.cfg"
    secedit /export /cfg $verifyCfg /quiet
    $verifyContent = Get-Content $verifyCfg
    $verifyLine = $verifyContent | Where-Object { $_ -match "LockoutBadCount" }
    $verifyValue = 0
    if ($verifyLine -match "=\s*(\d+)") { $verifyValue = [int]$Matches[1] }

    if ($verifyValue -ge 1 -and $verifyValue -le $maxAllowed) {
        Write-Host "[SUCCESS] Account lockout threshold set to '$verifyValue'. STIG WN11-AC-000035 is now satisfied." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Lockout threshold verification failed. Current value after remediation: '$verifyValue'. Review manually." -ForegroundColor Red
        exit 1
    }

    # Cleanup
    Remove-Item $newCfg -ErrorAction SilentlyContinue
    Remove-Item $verifyCfg -ErrorAction SilentlyContinue
}

# Cleanup
Remove-Item $tempCfg -ErrorAction SilentlyContinue
