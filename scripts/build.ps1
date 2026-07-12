# Build SentinelNet.exe con PyInstaller + smoke test.
# Uso: pwsh scripts/build.ps1 [-SkipSmoke]
param([switch]$SkipSmoke)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

pyinstaller --clean --noconfirm SentinelNet.spec
if ($LASTEXITCODE -ne 0) { Write-Error "pyinstaller fallito"; exit 1 }

if (-not $SkipSmoke) {
    # Smoke test: l'exe deve avviarsi e rispondere su HTTP entro 60s.
    $port = 18443
    $env:SENTINELNET_PORT = "$port"
    $env:SENTINELNET_NO_BROWSER = "true"
    $proc = Start-Process -FilePath "dist\SentinelNet.exe" -PassThru
    try {
        $ok = $false
        foreach ($i in 1..60) {
            Start-Sleep -Seconds 1
            if ($proc.HasExited) { break }
            try {
                Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -UseBasicParsing -TimeoutSec 2 -SkipCertificateCheck | Out-Null
                $ok = $true; break
            } catch {
                if ($_.Exception.Response) { $ok = $true; break }  # risponde (anche 401/redirect) = vivo
            }
        }
        if (-not $ok) { Write-Error "Smoke test fallito: exe non risponde"; exit 1 }
        Write-Host "Smoke test OK"
    } finally {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    }
}
Write-Host "Build OK: dist\SentinelNet.exe"
