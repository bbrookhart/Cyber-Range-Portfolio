#
.SYNOPSIS
    This PowerShell script ensures Windows Defender Credential Guard is enabled on
    Windows 11 domain-joined systems. Windows 11 introduces enhanced VBS defaults,
    but explicit STIG configuration ensures UEFI-locked Credential Guard is enforced
    to protect against Pass-the-Hash and credential theft via LSASS.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2017-8529
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000070
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11 Enterprise / Windows 11 Pro
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator on a domain-joined Windows 11 system with hardware VBS support
    (TPM 2.0, Secure Boot, and IOMMU/DMA protection required).
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000070.ps1
#>

# Confirm OS is Windows 11
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "[INFO] Operating System: $osCaption"
if ($osCaption -notmatch "Windows 11") {
    Write-Host "[WARN] This script is intended for Windows 11. Detected: $osCaption. Proceeding anyway..." -ForegroundColor Yellow
}

# ------------------------------------------------------------------
# Pre-flight: Query VBS/Device Guard status via WMI
# ------------------------------------------------------------------
$vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($vbsStatus) {
    Write-Host "[INFO] VirtualizationBasedSecurityStatus : $($vbsStatus.VirtualizationBasedSecurityStatus)"
    Write-Host "[INFO] SecurityServicesRunning           : $($vbsStatus.SecurityServicesRunning -join ', ')"
    Write-Host "[INFO] SecurityServicesConfigured        : $($vbsStatus.SecurityServicesConfigured -join ', ')"
} else {
    Write-Host "[WARN] Unable to query Device Guard WMI class. VBS hardware support may be limited on this system." -ForegroundColor Yellow
}

# ------------------------------------------------------------------
# Registry paths
# ------------------------------------------------------------------
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$cgPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

# ------------------------------------------------------------------
# Read current settings
# ------------------------------------------------------------------
$lsaCfg    = (Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
$enableVbs = (Get-ItemProperty -Path $cgPath  -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
$reqPlat   = (Get-ItemProperty -Path $cgPath  -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue).RequirePlatformSecurityFeatures

Write-Host "[INFO] LsaCfgFlags                       : $lsaCfg    (required: 1)"
Write-Host "[INFO] EnableVirtualizationBasedSecurity  : $enableVbs (required: 1)"
Write-Host "[INFO] RequirePlatformSecurityFeatures    : $reqPlat   (required: 3)"

# STIG required values:
#   LsaCfgFlags = 1  (Credential Guard with UEFI lock)
#   EnableVirtualizationBasedSecurity = 1
#   RequirePlatformSecurityFeatures = 3  (Secure Boot + DMA protection)
$compliant = ($lsaCfg -eq 1) -and ($enableVbs -eq 1) -and ($reqPlat -eq 3)

if ($compliant) {
    Write-Host "[PASS] Windows Defender Credential Guard is properly configured. STIG WN11-CC-000070 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Applying Credential Guard registry settings for Windows 11..." -ForegroundColor Yellow

# Ensure Device Guard base path exists
if (-not (Test-Path $cgPath)) {
    New-Item -Path $cgPath -Force | Out-Null
}

# Apply required settings
Set-ItemProperty -Path $cgPath  -Name "EnableVirtualizationBasedSecurity"  -Value 1 -Type DWord
Set-ItemProperty -Path $cgPath  -Name "RequirePlatformSecurityFeatures"    -Value 3 -Type DWord
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags"                        -Value 1 -Type DWord

# ------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------
$lsaNew    = (Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
$enableNew = (Get-ItemProperty -Path $cgPath  -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
$reqNew    = (Get-ItemProperty -Path $cgPath  -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue).RequirePlatformSecurityFeatures

if (($lsaNew -eq 1) -and ($enableNew -eq 1) -and ($reqNew -eq 3)) {
    Write-Host "[SUCCESS] Credential Guard settings applied successfully. STIG WN11-CC-000070 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A system restart is required for Credential Guard to become active." -ForegroundColor Cyan
    Write-Host "[INFO] Windows 11 with TPM 2.0 and Secure Boot will automatically activate hardware-based isolation after restart." -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] One or more settings were not applied correctly. Please review:" -ForegroundColor Red
    Write-Host "  LsaCfgFlags                      = $lsaNew  (expected: 1)"
    Write-Host "  EnableVirtualizationBasedSecurity = $enableNew (expected: 1)"
    Write-Host "  RequirePlatformSecurityFeatures   = $reqNew  (expected: 3)"
    exit 1
}
