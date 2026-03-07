#
.SYNOPSIS
    This PowerShell script ensures Windows 11 Diagnostic Data (Telemetry) is configured
    to the most restrictive allowable level. Windows 11 renamed the policy values but
    the STIG requirement remains: Security (0) for Enterprise/Education editions,
    or Basic/Required (1) for all other editions.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000260
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11 Enterprise / Pro / Education
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000260.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# Registry path for telemetry/diagnostic data policy
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName    = "AllowTelemetry"

# Determine Windows 11 edition to set the correct required value
$edition = (Get-WindowsEdition -Online -ErrorAction SilentlyContinue).Edition
Write-Host "[INFO] Detected Windows Edition: $edition"

# Windows 11 Enterprise and Education support level 0 (Security/Diagnostic data off)
# All other editions must use level 1 (Required/Basic) as the lowest permitted value
if ($edition -match "Enterprise|Education|EnterpriseG|EnterpriseGN") {
    $requiredValue = 0
    $levelName     = "Security / Diagnostic Data Off (0) - Enterprise/Education only"
} else {
    $requiredValue = 1
    $levelName     = "Required (Basic) Diagnostic Data (1)"
}

Write-Host "[INFO] Required AllowTelemetry value for '$edition': $levelName"

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] Registry path not found. Creating '$registryPath'..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read the current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current AllowTelemetry value: $currentValue"

if ($null -ne $currentValue -and $currentValue -le $requiredValue) {
    Write-Host "[PASS] Telemetry is already configured at or below the required level (current: $currentValue, required: <= $requiredValue). STIG WN11-CC-000260 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Setting AllowTelemetry to '$requiredValue' ($levelName)..." -ForegroundColor Yellow

# Apply the registry fix
Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -ne $newValue -and $newValue -le $requiredValue) {
    Write-Host "[SUCCESS] AllowTelemetry set to '$newValue' at '$registryPath'. STIG WN11-CC-000260 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] Note: Windows 11 may display this setting in the UI as 'Diagnostic data: Required diagnostic data'." -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] Failed to set telemetry level. Post-remediation value: '$newValue'. Please review manually." -ForegroundColor Red
    exit 1
}
