# Stops the FPolicy AV server (port 9898 by default) and ClamAV clamd (port 3310).
# With the ONTAP policy at -is-mandatory false, opens are then allowed unscanned;
# with -is-mandatory true they are denied until the scanner is back.
#
#   .\stop_av_scanner.ps1            stop both
#   .\stop_av_scanner.ps1 -KeepClamd stop only the FPolicy server

param(
    [int]$Port = 9898,
    [switch]$KeepClamd
)

$ports = @($Port)
if (-not $KeepClamd) { $ports += 3310 }

foreach ($p in $ports) {
    $listeners = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) {
        Write-Host "nothing listening on port $p"
        continue
    }
    foreach ($l in $listeners) {
        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        Stop-Process -Id $l.OwningProcess -Force
        Write-Host "stopped $($proc.ProcessName) (PID $($l.OwningProcess)) listening on port $p"
    }
}
