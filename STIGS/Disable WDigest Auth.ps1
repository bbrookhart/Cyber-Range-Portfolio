#
.SYNOPSIS
    This PowerShell script ensures WDigest Authentication is disabled on Windows 10,
    preventing cleartext credentials from being stored in LSASS memory where tools
    like Mimikatz can harvest them.
.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2014-6321
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000326
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000326.ps1
#>

# Registry path and value to disable WDigest cleartext credential caching
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$valueName    = "UseLogonCredential"
$valueData    = 0   # 0 = Disabled (do NOT store cleartext creds in memory)

# Check if registry path exists, create if missing
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] WDigest registry path not found. Creating path..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current UseLogonCredential value: $currentValue"

if ($currentValue -eq $valueData) {
    Write-Host "[PASS] WDigest Authentication is already disabled (UseLogonCredential = 0). STIG WN10-CC-000326 is satisfied." -ForegroundColor Green
    exit 0
}

if ($currentValue -eq 1) {
    Write-Host "[WARN] WDigest is ENABLED. Cleartext credentials are currently being cached in LSASS memory." -ForegroundColor Red
}

Write-Host "[REMEDIATE] Disabling WDigest cleartext credential storage..." -ForegroundColor Yellow

# Apply the fix
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($newValue -eq $valueData) {
    Write-Host "[SUCCESS] UseLogonCredential set to '$newValue' at '$registryPath'. STIG WN10-CC-000326 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A user logoff or system restart is recommended to flush any cached cleartext credentials from memory." -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] Failed to disable WDigest. Please review manually." -ForegroundColor Red
    exit 1
}
