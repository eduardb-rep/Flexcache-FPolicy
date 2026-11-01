# Starts the FPolicy AV scanner on this Windows host, each part in its own window:
#   - ClamAV clamd          listening on 127.0.0.1:3310
#   - fpolicy_av.py         listening on 0.0.0.0:<Port> (default 9898), called by ONTAP
# Safe to re-run: a part is skipped if its port is already listening.
#
# The kit can live in any folder (the runbook uses C:\AV LAB). Paths are taken from
# this script's location, and clamav\clamd.conf is rewritten on every start.
#
# Examples, in a PowerShell window opened in this folder:
#   Set-ExecutionPolicy -Scope Process Bypass     (once per window, if scripts are blocked)
#   .\start_av_scanner.ps1
#   .\start_av_scanner.ps1 -ShareMap 'dept1=\\svm1\c$\vol_dept1','dept2=\\svm1\c$\vol_dept2'
# From cmd.exe or a shortcut, give the share map as one comma-separated value:
#   powershell -ExecutionPolicy Bypass -File start_av_scanner.ps1 -ShareMap "dept1=\\svm1\c$\vol_dept1,dept2=\\svm1\c$\vol_dept2"
#
# -ShareMap: one entry per watched share, <share name as ONTAP reports it>=<UNC path that
# reaches the same files through a share that is NOT in the FPolicy scope>.

param(
    [string[]]$ShareMap = @('av_wa_cache=\\cluster2_svm1\c$\av_wa_cache',
                            'av_wb_cache=\\cluster2_svm1\c$\av_wb_cache'),
    [string]$Python = 'python',
    [int]$Port = 9898,
    [int]$MaxMB = 25
)

$ErrorActionPreference = 'Stop'
# accept 'a=..','b=..' as well as one "a=..,b=.." string; drop stray quotes
$ShareMap = @($ShareMap | ForEach-Object { $_ -split '[,;]' } |
              ForEach-Object { $_.Trim().Trim("'").Trim('"') } | Where-Object { $_ })
foreach ($m in $ShareMap) {
    if ($m -notmatch '^[^=]+=\\\\') { throw "Bad -ShareMap entry '$m': use <share>=\\<server>\<share>\<path>" }
}
$kit   = Split-Path -Parent $PSScriptRoot
$clam  = Join-Path $kit 'clamav'
$clamd = Join-Path $clam 'bin\clamav-1.5.4.win.x64\clamd.exe'
$conf  = Join-Path $clam 'clamd.conf'
$srv   = Join-Path $PSScriptRoot 'fpolicy_av.py'

function Test-Listening([int]$p) {
    [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
}

Write-Host "Kit folder: $kit"
if (-not (Test-Path $clamd)) { throw "clamd.exe not found: $clamd" }
if (-not (Test-Path $srv))   { throw "fpolicy_av.py not found: $srv" }
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw ("Python not found ('$Python'). Install Python 3.8 or later, for example " +
           "'winget install Python.Python.3.12', or pass -Python <path to python.exe>.")
}

# clamd.conf, written on every start so the paths always match this folder
@(
    'TCPSocket 3310',
    'TCPAddr 127.0.0.1',
    "DatabaseDirectory $clam\db",
    "LogFile $clam\clamd.log",
    'LogTime yes',
    'StreamMaxLength 100M',
    'MaxThreads 16',
    "CVDCertsDirectory $(Split-Path -Parent $clamd)\certs"
) | Set-Content -Path $conf -Encoding ASCII
Write-Host "Wrote $conf"

if (Test-Listening 3310) {
    Write-Host 'clamd already listening on 3310'
} else {
    Start-Process $clamd -ArgumentList "--config-file=`"$conf`"", '--foreground' -WindowStyle Minimized
    Write-Host 'clamd started (it loads its signatures in a few seconds; the full database takes longer)'
}

if (Test-Listening $Port) {
    Write-Host "FPolicy AV server already listening on $Port"
} else {
    $pyArgs = @('-u', "`"$srv`"", '--port', "$Port", '--max-mb', "$MaxMB", '--share-map') + $ShareMap
    Start-Process $Python -WorkingDirectory $PSScriptRoot -ArgumentList $pyArgs
    Write-Host "FPolicy AV server started on port $Port with share map: $($ShareMap -join ', ')"
}

Write-Host ''
Write-Host 'Decision log:   ' (Join-Path $PSScriptRoot 'fpolicy_av.log')
Write-Host 'ONTAP reconnects within a few minutes. To force it, on the cache cluster run:'
Write-Host '  vserver fpolicy engine-connect -node <node> -vserver <svm> -policy-name av_pol -server <this host IP>'
