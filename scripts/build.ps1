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
    # Bind forzato su loopback: app_settings.json puo' avere "host" sulla LAN,
    # ma lo smoke test interroga 127.0.0.1. Listener UDP spenti (evita
    # conflitti di porta con un'istanza reale in esecuzione).
    $env:SENTINELNET_HOST = "127.0.0.1"
    $env:SENTINELNET_OBS_ENABLE = "0"
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
        # L'exe one-file di PyInstaller e' un bootloader che avvia un processo
        # FIGLIO: fermare solo il padre lascia il figlio vivo e orfano, e l'exe
        # resta lockato -> la build successiva muore con "Accesso negato".
        # Si termina l'albero (/T), non il singolo processo.
        if (-not $proc.HasExited) {
            & taskkill.exe /PID $proc.Id /T /F *>$null
        }
        # Rete di sicurezza: se il padre e' gia' uscito il figlio e' stato
        # reparentato e /T non lo raggiunge. Si chiude solo cio' che gira da
        # QUESTA dist, mai un'istanza avviata altrove dall'utente.
        $distExe = (Resolve-Path "dist\SentinelNet.exe").Path
        Get-Process -Name SentinelNet -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -eq $distExe } |
            ForEach-Object {
                Write-Host "Smoke test: chiudo processo residuo PID $($_.Id)"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
    }
}
Write-Host "Build OK: dist\SentinelNet.exe"
