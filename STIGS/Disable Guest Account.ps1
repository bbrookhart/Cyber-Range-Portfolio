#
.SYNOPSIS
    This PowerShell script ensures the built-in Windows 11 Guest account is disabled,
    preventing unauthorized anonymous access to the local system and blocking a common
    lateral movement stepping stone.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000020
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-SO-000020.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Retrieve the built-in Guest account by well-known SID suffix -501
$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" }

if ($null -eq $guestAccount) {
    Write-Host "[INFO] Guest account not found on this system. STIG WN11-SO-000020 may already be satisfied." -ForegroundColor Cyan
    exit 0
}

Write-Host "[INFO] Found Guest account: '$($guestAccount.Name)' | Enabled: $($guestAccount.Enabled) | SID: $($guestAccount.SID)"

if (-not $guestAccount.Enabled) {
    Write-Host "[PASS] Guest account '$($guestAccount.Name)' is already disabled. STIG WN11-SO-000020 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Guest account '$($guestAccount.Name)' is currently ENABLED. Disabling..." -ForegroundColor Yellow

    # Disable the Guest account using SID for reliability
    Disable-LocalUser -SID $guestAccount.SID -ErrorAction Stop

    # Verify the change was applied
    $updatedAccount = Get-LocalUser -SID $guestAccount.SID -ErrorAction SilentlyContinue

    if ($null -ne $updatedAccount -and -not $updatedAccount.Enabled) {
        Write-Host "[SUCCESS] Guest account '$($updatedAccount.Name)' has been disabled. STIG WN11-SO-000020 is now satisfied." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to disable the Guest account. Current state: Enabled = $($updatedAccount.Enabled). Please review manually." -ForegroundColor Red
        exit 1
    }
}
