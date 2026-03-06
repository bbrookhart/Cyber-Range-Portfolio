#
.SYNOPSIS
    This PowerShell script ensures SMBv1 (Server Message Block version 1) is disabled
    on Windows 10, eliminating the legacy protocol exploited by EternalBlue/WannaCry
    and related ransomware families.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2017-0144, CVE-2017-0145
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000080
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000080.ps1
#>

# ------------------------------------------------------------------
# Method 1: Windows Feature (preferred on Windows 10)
# ------------------------------------------------------------------
Write-Host "[INFO] Checking SMBv1 feature state via Get-WindowsOptionalFeature..." -ForegroundColor Cyan

$smbFeature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue

if ($smbFeature) {
    Write-Host "[INFO] SMB1Protocol feature state: $($smbFeature.State)"

    if ($smbFeature.State -eq "Disabled") {
        Write-Host "[PASS] SMBv1 Windows Feature is already disabled. STIG WN10-SO-000080 is satisfied." -ForegroundColor Green
    } else {
        Write-Host "[REMEDIATE] Disabling SMBv1 Windows Feature..." -ForegroundColor Yellow
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
        Write-Host "[SUCCESS] SMBv1 feature has been disabled. STIG WN10-SO-000080 is now satisfied." -ForegroundColor Green
        Write-Host "[INFO] A system restart is required to complete removal of SMBv1." -ForegroundColor Cyan
    }
} else {
    Write-Host "[INFO] SMB1Protocol optional feature not found. Falling back to registry/configuration check..." -ForegroundColor Yellow
}

# ------------------------------------------------------------------
# Method 2: Registry enforcement (defense-in-depth)
# ------------------------------------------------------------------
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$valueName    = "SMB1"
$valueData    = 0   # 0 = Disabled

if (-not (Test-Path $registryPath)) {
    Write-Host "[INFO] LanmanServer registry path not found. Skipping registry check." -ForegroundColor Yellow
} else {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    Write-Host "[INFO] Current SMB1 registry value: $currentValue"

    if ($currentValue -eq $valueData) {
        Write-Host "[PASS] SMBv1 registry value is already set to disabled." -ForegroundColor Green
    } else {
        Write-Host "[REMEDIATE] Setting SMB1 registry value to 0 (disabled)..." -ForegroundColor Yellow
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

        $newValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
        if ($newValue -eq $valueData) {
            Write-Host "[SUCCESS] SMB1 registry value set to '$newValue'. Defense-in-depth registry control applied." -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Registry change failed. Review manually." -ForegroundColor Red
            exit 1
        }
    }
}

# ------------------------------------------------------------------
# Method 3: Confirm via Get-SmbServerConfiguration
# ------------------------------------------------------------------
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig) {
    Write-Host "[INFO] Get-SmbServerConfiguration EnableSMB1Protocol: $($smbConfig.EnableSMB1Protocol)"
    if ($smbConfig.EnableSMB1Protocol -eq $true) {
        Write-Host "[REMEDIATE] Disabling SMBv1 via Set-SmbServerConfiguration..." -ForegroundColor Yellow
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Host "[SUCCESS] SMBv1 disabled via SmbServerConfiguration." -ForegroundColor Green
    }
}
