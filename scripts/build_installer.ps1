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

# --- WinSW (wrapper del servizio Windows) ------------------------------------
# Un exe PyInstaller non e' un servizio: non risponde mai all'SCM, quindi
# Windows lo ucciderebbe con "il servizio non ha risposto in tempo". WinSW sta
# in mezzo. Non e' versionato (binario di terze parti in un repo pubblico): si
# scarica una volta e si verifica l'hash, perche' un wrapper che gira come
# LocalSystem e' l'ultimo posto dove accettare un download non controllato.
$winswVersion = 'v2.12.0'
$winswSha256  = 'B5066B7BBDFBA1293E5D15CDA3CAAEA88FBEAB35BD5B38C41C913D492AADFC4F'
$winswPath    = 'installer\vendor\WinSW.exe'

if (-not (Test-Path $winswPath)) {
    # NET461 e non il build self-contained da 18 MB: .NET Framework 4.6.1 c'e'
    # gia' su Windows 10 1607 e successivi, e l'installer chiede comunque x64.
    $url = "https://github.com/winsw/winsw/releases/download/$winswVersion/WinSW.NET461.exe"
    Write-Host "Scarico WinSW $winswVersion..."
    New-Item -ItemType Directory -Force -Path (Split-Path $winswPath) | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $winswPath -UseBasicParsing
}
$hash = (Get-FileHash $winswPath -Algorithm SHA256).Hash
if ($hash -ne $winswSha256) {
    Remove-Item $winswPath -Force -ErrorAction SilentlyContinue
    Write-Error "WinSW: hash inatteso ($hash). File rimosso, rilancia la build."
    exit 1
}
Write-Host "WinSW ${winswVersion}: hash verificato"

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
