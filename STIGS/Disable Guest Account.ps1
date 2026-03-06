#
.SYNOPSIS
    This PowerShell script ensures the built-in Windows Guest account is disabled,
    preventing unauthorized anonymous access to the local system.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000020
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000020.ps1
#>

# Retrieve the built-in Guest account (SID ending in -501)
$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" }

if ($null -eq $guestAccount) {
    Write-Host "[INFO] Guest account not found on this system. STIG WN10-SO-000020 may already be satisfied." -ForegroundColor Cyan
    exit 0
}

Write-Host "[INFO] Found Guest account: '$($guestAccount.Name)' | Enabled: $($guestAccount.Enabled)"

if (-not $guestAccount.Enabled) {
    Write-Host "[PASS] Guest account '$($guestAccount.Name)' is already disabled. STIG WN10-SO-000020 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Disabling Guest account '$($guestAccount.Name)'..." -ForegroundColor Yellow

    # Disable the Guest account
    Disable-LocalUser -SID $guestAccount.SID -ErrorAction Stop

    # Verify the change
    $updatedAccount = Get-LocalUser -SID $guestAccount.SID
    if (-not $updatedAccount.Enabled) {
        Write-Host "[SUCCESS] Guest account '$($guestAccount.Name)' has been disabled. STIG WN10-SO-000020 is now satisfied." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to disable the Guest account. Please review manually." -ForegroundColor Red
        exit 1
    }
}
