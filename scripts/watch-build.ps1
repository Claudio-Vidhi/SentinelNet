# Rebuild continuo: osserva i sorgenti e rilancia build.ps1 con debounce.
# Uso: pwsh scripts/watch-build.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$watcher = New-Object System.IO.FileSystemWatcher $root, '*.py'
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$tmpl = New-Object System.IO.FileSystemWatcher (Join-Path $root 'templates'), '*.*'
$tmpl.IncludeSubdirectories = $true
$tmpl.EnableRaisingEvents = $true

Write-Host "In ascolto su $root (*.py, templates/). Ctrl+C per uscire."
$pending = $false
$action = { $script:pending = $true }
foreach ($w in @($watcher, $tmpl)) {
    Register-ObjectEvent $w Changed -Action $action | Out-Null
    Register-ObjectEvent $w Created -Action $action | Out-Null
    Register-ObjectEvent $w Renamed -Action $action | Out-Null
}
while ($true) {
    Start-Sleep -Seconds 5   # debounce
    if ($script:pending) {
        $script:pending = $false
        Write-Host "`n=== Modifica rilevata: rebuild $(Get-Date -Format HH:mm:ss) ==="
        & pwsh -File (Join-Path $PSScriptRoot 'build.ps1') -SkipSmoke
    }
}
