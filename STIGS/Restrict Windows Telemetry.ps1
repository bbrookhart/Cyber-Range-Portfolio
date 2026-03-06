#
.SYNOPSIS
    This PowerShell script ensures Windows Telemetry (Diagnostic Data) is configured
    to the most restrictive allowable level (Security/0 for Enterprise, or Basic/1 for
    other editions), minimizing data transmitted to Microsoft and reducing attack surface.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000260
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10 Enterprise / Pro
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000260.ps1
#>

# Registry path for telemetry policy
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName    = "AllowTelemetry"

# Determine Windows edition to set correct required value
# Enterprise/Education support level 0 (Security), others require minimum level 1 (Basic)
$edition = (Get-WindowsEdition -Online -ErrorAction SilentlyContinue).Edition

Write-Host "[INFO] Detected Windows Edition: $edition"

if ($edition -match "Enterprise|Education") {
    $requiredValue = 0   # Security level - most restrictive, Enterprise/Education only
    $levelName     = "Security (0)"
} else {
    $requiredValue = 1   # Basic level - required minimum for non-Enterprise editions
    $levelName     = "Basic (1)"
}

Write-Host "[INFO] Required AllowTelemetry value for this edition: $levelName"

# Create registry path if missing
if (-not (Test-Path $registryPath)) {
    Write-Host "[REMEDIATE] Registry path not found. Creating path..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# Read current value
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

Write-Host "[INFO] Current AllowTelemetry value: $currentValue"

if ($null -ne $currentValue -and $currentValue -le $requiredValue) {
    Write-Host "[PASS] Telemetry is already configured at or below the required level (current: $currentValue, required: <= $requiredValue). STIG WN10-CC-000260 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Setting AllowTelemetry to '$requiredValue' ($levelName)..." -ForegroundColor Yellow

# Apply the registry fix
Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord

# Verify
$newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($newValue -le $requiredValue) {
    Write-Host "[SUCCESS] AllowTelemetry set to '$newValue' ($levelName) at '$registryPath'. STIG WN10-CC-000260 is now satisfied." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to set telemetry level. Please review manually." -ForegroundColor Red
    exit 1
}
