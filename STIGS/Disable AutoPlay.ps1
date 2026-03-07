#
.SYNOPSIS
    This PowerShell script ensures AutoPlay is disabled for all drives on Windows 11,
    preventing automatic execution of malicious code from removable media such as
    USB drives and optical discs — a common initial access vector.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000038
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000038.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Registry path and settings for disabling AutoPlay on all drives
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName    = "NoDriveTypeAutoRun"
$valueData    = 255   # 0xFF - Disables AutoPlay on ALL drive types

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] Registry path not found. Creating '$registryPath'..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current NoDriveTypeAutoRun value: $currentValue (required: 255)"

if ($currentValue -eq $valueData) {
    Write-Host "[PASS] AutoPlay is already disabled for all drives (NoDriveTypeAutoRun = $currentValue). STIG WN11-CC-000038 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Setting NoDriveTypeAutoRun to '$valueData' to disable AutoPlay on all drive types..." -ForegroundColor Yellow

# Apply the registry setting
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($newValue -eq $valueData) {
    Write-Host "[SUCCESS] NoDriveTypeAutoRun set to '$newValue' at '$registryPath'. STIG WN11-CC-000038 is now satisfied." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to apply AutoPlay registry setting. Current value: '$newValue'. Please review manually." -ForegroundColor Red
    exit 1
}
