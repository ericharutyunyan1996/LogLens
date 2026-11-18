<#
.SYNOPSIS
  Local code-signing helper for LogLens installers (self-signed certificate + signtool).

.DESCRIPTION
  Run once per machine:   powershell -ExecutionPolicy Bypass -File tools\signing.ps1 -Setup
  (add -Trust from an ELEVATED prompt so Windows treats the certificate as a trusted publisher on THIS machine;
   without it the MSI is signed but still shows "Unknown publisher" until the cert is trusted).
  Sign a file:            powershell -ExecutionPolicy Bypass -File tools\signing.ps1 -Sign dist\LogLens-0.1.0.msi
  tools\build.py calls -Sign automatically when a certificate exists.

  A self-signed certificate is for LOCAL TESTING ONLY. Anyone else's machine will not trust it. Public releases need a
  real code-signing certificate (see .github\workflows\release.yml, secrets WINDOWS_CERT_PFX_BASE64 / _PASSWORD).
  Nothing here is stored in the repo: the key lives in your user certificate store (Cert:\CurrentUser\My); the public
  .cer is exported to .signing\ (git-ignored).
#>
[CmdletBinding()]
param(
    [switch]$Setup,
    [switch]$Trust,
    [switch]$Untrust,
    [string]$Sign,
    [string]$Subject = $(if ($env:SIGN_SUBJECT) { $env:SIGN_SUBJECT } else { 'CN=LogLens Local Dev, O=LogLens' }),
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $root '.signing'

function Get-LocalCert {
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date).AddDays(7) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path $kits) {
        $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like '*\x64\*' } | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

if ($Setup) {
    $cert = Get-LocalCert
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -KeyAlgorithm RSA -KeyLength 3072 `
            -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -CertStoreLocation Cert:\CurrentUser\My `
            -NotAfter (Get-Date).AddYears(2)
        Write-Host "Created certificate $($cert.Thumbprint)"
    } else { Write-Host "Using existing certificate $($cert.Thumbprint)" }
    New-Item -ItemType Directory -Force $certDir | Out-Null
    $cer = Join-Path $certDir 'LogLensLocalDev.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Write-Host "Public certificate: $cer"
    if ($Trust) {
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $admin) { throw '-Trust needs an elevated (administrator) PowerShell.' }
        # A self-signed cert must be in Trusted Root (chain) AND Trusted Publishers (no publisher prompt).
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Host 'Certificate trusted on this machine. Remove later with: tools\signing.ps1 -Untrust (elevated).'
    } else {
        Write-Host 'Not trusted yet: re-run with -Trust from an elevated prompt to remove "Unknown publisher" locally.'
    }
    return
}

if ($Untrust) {
    foreach ($store in 'Root', 'TrustedPublisher') {
        Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object { $_.Subject -eq $Subject } | Remove-Item
    }
    Write-Host 'Removed the local LogLens certificate from the machine trust stores.'
    return
}

if ($Sign) {
    $cert = Get-LocalCert
    if (-not $cert) { throw 'No local signing certificate. Run: tools\signing.ps1 -Setup' }
    $file = (Resolve-Path $Sign).Path
    $signtool = Find-SignTool
    if ($signtool) {
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /tr $TimestampUrl /td SHA256 /d 'LogLens' $file
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
    } else {
        Write-Warning 'signtool.exe not found (install the Windows SDK: winget install Microsoft.WindowsSDK.10.0.26100). Falling back to Set-AuthenticodeSignature.'
        $r = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampUrl
        if ($r.Status -ne 'Valid' -and $r.Status -ne 'UnknownError') { throw "Signing failed: $($r.Status) $($r.StatusMessage)" }
    }
    $check = Get-AuthenticodeSignature $file
    Write-Host "Signed $file -> $($check.Status) ($($check.SignerCertificate.Subject))"
    return
}

Write-Host 'Use -Setup [-Trust], -Untrust (elevated) or -Sign <file>.'
