#
.SYNOPSIS
    This PowerShell script ensures WDigest Authentication is disabled on Windows 11,
    preventing cleartext credentials from being stored in LSASS memory where tools
    like Mimikatz can harvest them during post-exploitation.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2014-6321
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000326
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000326.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Registry path and value to disable WDigest cleartext credential caching
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$valueName    = "UseLogonCredential"
$valueData    = 0   # 0 = Disabled — do NOT cache cleartext credentials in LSASS

# Create registry path if missing
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] WDigest registry path not found. Creating '$registryPath'..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current UseLogonCredential value: $currentValue (required: 0)"

if ($currentValue -eq $valueData) {
    Write-Host "[PASS] WDigest is already disabled (UseLogonCredential = 0). STIG WN11-CC-000326 is satisfied." -ForegroundColor Green
    exit 0
}

if ($currentValue -eq 1) {
    Write-Host "[CRITICAL] WDigest is ENABLED. Cleartext credentials are currently being cached in LSASS memory and are vulnerable to Mimikatz-style harvesting." -ForegroundColor Red
} else {
    Write-Host "[REMEDIATE] UseLogonCredential is '$currentValue'. Applying secure value of 0..." -ForegroundColor Yellow
}

# Apply the fix
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($newValue -eq $valueData) {
    Write-Host "[SUCCESS] WDigest disabled (UseLogonCredential = $newValue) at '$registryPath'. STIG WN11-CC-000326 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A user logoff or system restart is recommended to flush any cached cleartext credentials from LSASS memory." -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] Failed to disable WDigest. Current value after remediation: '$newValue'. Please review manually." -ForegroundColor Red
    exit 1
}
