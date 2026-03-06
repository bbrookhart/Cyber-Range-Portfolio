#
.SYNOPSIS
    This PowerShell script ensures Windows Defender Credential Guard is enabled on
    Windows 10/11 domain-joined systems, protecting credential hashes from theft
    via Pass-the-Hash and similar attacks by isolating them in a virtualized container.
.NOTES
    Author          : Brian Brookhart
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-03-06
    Last Modified   : 2025-03-06
    Version         : 1.0
    CVEs            : CVE-2017-8529
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000070
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10 Enterprise / Windows 11 Enterprise
    PowerShell Ver. : 5.1
.USAGE
    Run as Administrator on a domain-joined system with Virtualization-Based Security
    (VBS) hardware support (Secure Boot + IOMMU required).
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000070.ps1
#>

# ------------------------------------------------------------------
# Pre-flight: confirm Virtualization-Based Security is supported
# ------------------------------------------------------------------
$vbsStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue)

if ($null -eq $vbsStatus) {
    Write-Host "[WARN] Unable to query Device Guard status. Ensure the system supports VBS and the script is run as Administrator." -ForegroundColor Yellow
}

# ------------------------------------------------------------------
# Registry paths for Credential Guard
# ------------------------------------------------------------------
$lsaPath        = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$cgPath         = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$cgFeaturesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

# ------------------------------------------------------------------
# Check current Credential Guard configuration
# ------------------------------------------------------------------
$lsaCfg    = (Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
$enableVbs = (Get-ItemProperty -Path $cgPath  -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
$reqPlat   = (Get-ItemProperty -Path $cgPath  -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue).RequirePlatformSecurityFeatures

Write-Host "[INFO] Current LsaCfgFlags                      : $lsaCfg"
Write-Host "[INFO] EnableVirtualizationBasedSecurity         : $enableVbs"
Write-Host "[INFO] RequirePlatformSecurityFeatures           : $reqPlat"

# Values required by STIG:
#   LsaCfgFlags = 1  (Credential Guard enabled with UEFI lock)
#   EnableVirtualizationBasedSecurity = 1
#   RequirePlatformSecurityFeatures = 3  (Secure Boot + DMA protection)

$compliant = ($lsaCfg -eq 1) -and ($enableVbs -eq 1) -and ($reqPlat -eq 3)

if ($compliant) {
    Write-Host "[PASS] Windows Defender Credential Guard is properly configured. STIG WN10-CC-000070 is satisfied." -ForegroundColor Green
    exit 0
}

Write-Host "[REMEDIATE] Applying Credential Guard registry settings..." -ForegroundColor Yellow

# Ensure Device Guard base path exists
if (-not (Test-Path $cgPath)) {
    New-Item -Path $cgPath -Force | Out-Null
}

# Enable Virtualization-Based Security
Set-ItemProperty -Path $cgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

# Require Secure Boot + DMA Protection (value 3)
Set-ItemProperty -Path $cgPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord

# Enable Credential Guard with UEFI lock (LsaCfgFlags = 1)
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord

# ------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------
$lsaNew    = (Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
$enableNew = (Get-ItemProperty -Path $cgPath  -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
$reqNew    = (Get-ItemProperty -Path $cgPath  -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue).RequirePlatformSecurityFeatures

if (($lsaNew -eq 1) -and ($enableNew -eq 1) -and ($reqNew -eq 3)) {
    Write-Host "[SUCCESS] Credential Guard settings applied successfully. STIG WN10-CC-000070 is now satisfied." -ForegroundColor Green
    Write-Host "[INFO] A system restart is required for Credential Guard to become active." -ForegroundColor Cyan
} else {
    Write-Host "[ERROR] One or more registry values were not set correctly. Please review manually." -ForegroundColor Red
    Write-Host "  LsaCfgFlags                      = $lsaNew  (expected: 1)"
    Write-Host "  EnableVirtualizationBasedSecurity = $enableNew (expected: 1)"
    Write-Host "  RequirePlatformSecurityFeatures   = $reqNew  (expected: 3)"
    exit 1
}
