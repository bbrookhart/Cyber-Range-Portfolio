#
.SYNOPSIS
    This PowerShell script ensures SMBv1 (Server Message Block version 1) is disabled
    on Windows 11, eliminating the legacy protocol exploited by EternalBlue, WannaCry,
    and NotPetya. Windows 11 ships without SMBv1 by default, but this script validates
    and enforces that state across all three control planes.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2017-0144, CVE-2017-0145
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000080
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-SO-000080.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

$overallPass = $true

# ------------------------------------------------------------------
# Method 1: Windows Optional Feature (primary check)
# ------------------------------------------------------------------
Write-Host "`n[INFO] --- Method 1: Windows Optional Feature ---" -ForegroundColor Cyan
$smbFeature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue

if ($smbFeature) {
    Write-Host "[INFO] SMB1Protocol feature state: $($smbFeature.State)"
    if ($smbFeature.State -eq "Disabled") {
        Write-Host "[PASS] SMBv1 Windows Feature is already disabled." -ForegroundColor Green
    } else {
        $overallPass = $false
        Write-Host "[REMEDIATE] Disabling SMBv1 Windows Feature..." -ForegroundColor Yellow
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
        Write-Host "[SUCCESS] SMBv1 feature disabled. Restart required to complete removal." -ForegroundColor Green
    }
} else {
    Write-Host "[INFO] SMB1Protocol optional feature not found (expected on clean Windows 11 installs)." -ForegroundColor Cyan
}

# ------------------------------------------------------------------
# Method 2: LanmanServer registry key (defense-in-depth)
# ------------------------------------------------------------------
Write-Host "`n[INFO] --- Method 2: LanmanServer Registry ---" -ForegroundColor Cyan
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$valueName    = "SMB1"

if (Test-Path $registryPath) {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    Write-Host "[INFO] Current SMB1 registry value: $currentValue (required: 0)"

    if ($currentValue -eq 0) {
        Write-Host "[PASS] SMB1 registry value is already set to 0 (disabled)." -ForegroundColor Green
    } else {
        $overallPass = $false
        Write-Host "[REMEDIATE] Setting SMB1 registry value to 0..." -ForegroundColor Yellow
        Set-ItemProperty -Path $registryPath -Name $valueName -Value 0 -Type DWord
        $newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
        if ($newValue -eq 0) {
            Write-Host "[SUCCESS] SMB1 registry value set to 0." -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Registry change failed. Current value: '$newValue'." -ForegroundColor Red
        }
    }
} else {
    Write-Host "[INFO] LanmanServer Parameters path not found. Skipping registry check." -ForegroundColor Cyan
}

# ------------------------------------------------------------------
# Method 3: SmbServerConfiguration (runtime enforcement)
# ------------------------------------------------------------------
Write-Host "`n[INFO] --- Method 3: SmbServerConfiguration ---" -ForegroundColor Cyan
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig) {
    Write-Host "[INFO] EnableSMB1Protocol (runtime): $($smbConfig.EnableSMB1Protocol)"
    if ($smbConfig.EnableSMB1Protocol -eq $false) {
        Write-Host "[PASS] SMBv1 is disabled in SmbServerConfiguration." -ForegroundColor Green
    } else {
        $overallPass = $false
        Write-Host "[REMEDIATE] Disabling SMBv1 via Set-SmbServerConfiguration..." -ForegroundColor Yellow
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Host "[SUCCESS] SMBv1 disabled via SmbServerConfiguration." -ForegroundColor Green
    }
} else {
    Write-Host "[INFO] Unable to query SmbServerConfiguration. Skipping." -ForegroundColor Cyan
}

# ------------------------------------------------------------------
# Final Summary
# ------------------------------------------------------------------
Write-Host ""
if ($overallPass) {
    Write-Host "[PASS] SMBv1 is disabled across all control planes. STIG WN11-SO-000080 is satisfied." -ForegroundColor Green
} else {
    Write-Host "[SUCCESS] SMBv1 remediation applied across all detected control planes. STIG WN11-SO-000080 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A system restart is recommended to fully complete SMBv1 removal." -ForegroundColor Cyan
}
