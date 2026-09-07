# Build SentinelNet-Setup-<version>.exe con Inno Setup.
#
# La versione arriva SEMPRE da core/version.py: passarla a mano al compilatore
# e' il modo in cui un installer finisce per dichiarare una versione diversa da
# quella che l'exe stampa su /api/version.
#
# Uso: pwsh scripts/build_installer.ps1 [-SkipExe]
#   -SkipExe   riusa dist\SentinelNet.exe invece di ricostruirlo.
param([switch]$SkipExe)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

# --- versione, dall'unica fonte di verita' ----------------------------------
$versionPy = Get-Content 'core\version.py' -Raw
if ($versionPy -notmatch '__version__\s*=\s*"([^"]+)"') {
    Write-Error 'core/version.py: __version__ non trovato.'; exit 1
}
$version = $Matches[1]
Write-Host "SentinelNet $version"

# --- exe ---------------------------------------------------------------------
if (-not $SkipExe) {
    & pwsh scripts\build.ps1
    if ($LASTEXITCODE -ne 0) { Write-Error 'build.ps1 fallito'; exit 1 }
}
if (-not (Test-Path 'dist\SentinelNet.exe')) {
    Write-Error 'dist\SentinelNet.exe assente: esegui senza -SkipExe.'; exit 1
}

# --- compilatore Inno --------------------------------------------------------
# winget lo installa sotto LOCALAPPDATA (per-utente), l'installer manuale sotto
# Program Files (x86). Si cercano entrambi prima di arrendersi.
$isccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host 'ISCC.exe non trovato. Installa Inno Setup 6:'
    Write-Host '  winget install --id JRSoftware.InnoSetup'
    Write-Host 'Cercato in:'
    $isccCandidates | ForEach-Object { Write-Host "  $_" }
    exit 1
}

& $iscc "/DAppVersion=$version" 'installer\SentinelNet.iss'
if ($LASTEXITCODE -ne 0) { Write-Error 'ISCC fallito'; exit 1 }

$setup = "dist\SentinelNet-Setup-$version.exe"
if (-not (Test-Path $setup)) { Write-Error "Atteso $setup, non prodotto"; exit 1 }
$size = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host "Installer OK: $setup ($size MB)"
