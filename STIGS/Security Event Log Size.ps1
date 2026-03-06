#
.SYNOPSIS
    This PowerShell script ensures the maximum size of the Windows Security event log
    is configured to at least 1024000 KB (1 GB), preserving sufficient audit history
    for forensic and compliance purposes.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000505
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AU-000505.ps1
#>

# Define the registry path and required minimum value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valueName    = "MaxSize"
$minValue     = 1024000   # 1 GB in KB (STIG minimum)
$setValue     = 1024000   # Value to apply during remediation

# Check if the registry path exists
if (Test-Path $registryPath) {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    if ($null -ne $currentValue -and $currentValue -ge $minValue) {
        Write-Host "[PASS] Security event log MaxSize is '$currentValue' KB. STIG WN10-AU-000505 is satisfied." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[REMEDIATE] Current MaxSize is '$currentValue' KB (required: >= $minValue KB). Applying fix..." -ForegroundColor Yellow
    }
} else {
    Write-Host "[REMEDIATE] Registry path not found. Creating path and setting value..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the MaxSize registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $setValue -Type DWord

# Verify the change
$verifyValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
if ($verifyValue -ge $minValue) {
    Write-Host "[SUCCESS] Security event log MaxSize set to '$verifyValue' KB at '$registryPath'. STIG WN10-AU-000505 is now satisfied." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to apply the registry change. Please review manually." -ForegroundColor Red
    exit 1
}
