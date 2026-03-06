#
.SYNOPSIS
    This PowerShell script ensures that Windows PowerShell 2.0 is disabled on Windows 10,
    preventing use of the older, less secure version of PowerShell that lacks modern logging
    and security controls.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000197
.TESTED ON
    Date(s) Tested  : Brian Brookhart
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000197.ps1
#>

# Check current state of PowerShell 2.0 feature
$feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue

if ($null -eq $feature) {
    Write-Host "[INFO] Unable to query PowerShell 2.0 feature state. Ensure script is run as Administrator." -ForegroundColor Yellow
    exit 1
}

if ($feature.State -eq "Disabled") {
    Write-Host "[PASS] PowerShell 2.0 (MicrosoftWindowsPowerShellV2Root) is already disabled. STIG WN10-CC-000197 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[REMEDIATE] Disabling PowerShell 2.0..." -ForegroundColor Yellow

    # Disable PowerShell 2.0 root feature
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop

    # Also disable the engine sub-feature if present
    $engineFeature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction SilentlyContinue
    if ($engineFeature -and $engineFeature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart -ErrorAction Stop
    }

    Write-Host "[SUCCESS] PowerShell 2.0 has been disabled. STIG WN10-CC-000197 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A system restart may be required for changes to take full effect." -ForegroundColor Cyan
}
