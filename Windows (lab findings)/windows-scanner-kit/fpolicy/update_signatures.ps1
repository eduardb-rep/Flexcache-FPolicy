# Optional: downloads the official ClamAV signature database with freshclam.
# The kit ships only a test signature that detects the EICAR test string; real
# detection needs the official database (about 350 MB, HTTPS to database.clamav.net).
#
#   .\update_signatures.ps1                  download / update the official database
#   .\update_signatures.ps1 -Proxy proxy.example.com:3128
#
# clamd picks up new signatures by itself within 10 minutes (SelfCheck), or at once
# after .\stop_av_scanner.ps1 and .\start_av_scanner.ps1.
# Run it at most a few times a day: the ClamAV CDN blocks clients that poll too often.

param(
    [string]$Proxy = ''
)

$ErrorActionPreference = 'Stop'
$kit  = Split-Path -Parent $PSScriptRoot
$clam = Join-Path $kit 'clamav'
$bin  = Join-Path $clam 'bin\clamav-1.5.4.win.x64'
$fc   = Join-Path $bin 'freshclam.exe'
$conf = Join-Path $clam 'freshclam.conf'

if (-not (Test-Path $fc)) { throw "freshclam.exe not found: $fc" }

$lines = @(
    "DatabaseDirectory $clam\db",
    "UpdateLogFile $clam\freshclam.log",
    'LogTime yes',
    'DatabaseMirror database.clamav.net',
    "CVDCertsDirectory $bin\certs"
)
if ($Proxy) {
    $parts = $Proxy -split ':'
    $lines += "HTTPProxyServer $($parts[0])"
    if ($parts.Count -gt 1) { $lines += "HTTPProxyPort $($parts[1])" }
}
$lines | Set-Content -Path $conf -Encoding ASCII
Write-Host "Wrote $conf"

& $fc "--config-file=$conf" --stdout
if ($LASTEXITCODE -ne 0) {
    throw "freshclam failed (exit $LASTEXITCODE): check HTTPS access to database.clamav.net"
}
Write-Host 'Signature files:'
Get-ChildItem (Join-Path $clam 'db') | Format-Table Name, @{n='MB'; e={[math]::Round($_.Length / 1MB, 1)}} -AutoSize
