#
.SYNOPSIS
    This PowerShell script ensures the maximum size of the Windows 11 Security event log
    is configured to at least 1024000 KB (1 GB), preserving sufficient audit history
    for forensic investigation and compliance requirements.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000505
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-AU-000505.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Registry path and required minimum size
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valueName    = "MaxSize"
$minValue     = 1024000   # 1 GB in KB (STIG WN11-AU-000505 minimum)
$setValue     = 1024000   # Value to apply during remediation

# Create registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] Registry path '$registryPath' not found. Creating..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current MaxSize value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current Security event log MaxSize: $currentValue KB"

if ($null -ne $currentValue -and $currentValue -ge $minValue) {
    Write-Host "[PASS] Security event log MaxSize is '$currentValue' KB (required: >= $minValue KB). STIG WN11-AU-000505 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] MaxSize is '$currentValue' KB. Applying required value of '$setValue' KB..." -ForegroundColor Yellow

# Set the MaxSize value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $setValue -Type DWord

# Verify the change
$verifyValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -ne $verifyValue -and $verifyValue -ge $minValue) {
    Write-Host "[SUCCESS] Security event log MaxSize set to '$verifyValue' KB at '$registryPath'. STIG WN11-AU-000505 is now satisfied." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Registry update failed or verification mismatch. Current value: '$verifyValue'. Please review manually." -ForegroundColor Red
    exit 1
}
