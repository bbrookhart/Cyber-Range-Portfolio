#
.SYNOPSIS
    This PowerShell script ensures AutoPlay is disabled for all drives on Windows 10,
    preventing automatic execution of malicious code from removable media such as
    USB drives and optical discs.
.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000038
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000038.ps1
#>

# Registry path and settings for disabling AutoPlay on all drives
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName    = "NoDriveTypeAutoRun"
$valueData    = 255   # 0xFF - Disables AutoPlay on ALL drive types

# Check if registry path exists
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] Registry path not found. Creating path..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current NoDriveTypeAutoRun value: $currentValue"

if ($currentValue -eq $valueData) {
    Write-Host "[PASS] AutoPlay is already disabled for all drives (NoDriveTypeAutoRun = $currentValue). STIG WN10-CC-000038 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Setting NoDriveTypeAutoRun to '$valueData' to disable AutoPlay on all drives..." -ForegroundColor Yellow

# Apply the registry setting
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($newValue -eq $valueData) {
    Write-Host "[SUCCESS] NoDriveTypeAutoRun set to '$newValue' at '$registryPath'. STIG WN10-CC-000038 is now satisfied." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to apply the registry setting. Please review manually." -ForegroundColor Red
    exit 1
}
