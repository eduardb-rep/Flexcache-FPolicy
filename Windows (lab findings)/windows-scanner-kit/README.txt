FlexCache AV scanner kit - Windows (FPolicy server + ClamAV)
===========================================================

Everything the Windows scanner in the runbook needs, except Python itself.
See FlexCache_AV_Windows_Lab_Runbook.html (next to this folder) for how it works.

This is a lab prototype, provided as is. It is not a NetApp-supported antivirus
integration. NetApp's supported design for FlexCache is on-access Vscan with a partner
antivirus engine at the origin, plus scheduled on-demand scans (TR-4743).


1. Contents
-----------
  fpolicy\fpolicy_av.py            FPolicy server (Python, standard library only)
  fpolicy\start_av_scanner.ps1     starts clamd and the FPolicy server (safe to re-run)
  fpolicy\stop_av_scanner.ps1      stops them
  fpolicy\update_signatures.ps1    optional: downloads the official ClamAV signatures
  clamav\bin\clamav-1.5.4.win.x64\ ClamAV 1.5.4 for Windows x64 (runtime files)
  clamav\db\lab_eicar.ndb          test signature: detects the EICAR string anywhere in a file
  LICENSES.txt                     licences and source of the third-party software

  Created at run time: clamav\clamd.conf, clamav\clamd.log, fpolicy\fpolicy_av.log,
  fpolicy\fpolicy_av_raw.log (first 10 raw requests).


2. Prerequisites
----------------
  - Windows Server 2016 or later (or Windows 10/11), x64.
  - Python 3.8 or later on the PATH: https://www.python.org/downloads/windows/
    or:  winget install Python.Python.3.12
  - ONTAP 9.14.1 or later on the cache cluster (FPolicy on FlexCache volumes over SMB).
  - Network: TCP 9898 from the cache SVM's data LIFs to this host; TCP 445 from this
    host to the SVM. Place the host close to the cache: every screened open waits for it.
  - A way to read the watched files through a share that is NOT in the FPolicy scope,
    so the scanner's own reads are not screened. The lab used the c$ administrative share
    as a domain administrator. For a pilot, prefer a dedicated hidden share (for example
    scan$) with read-only access for a dedicated service account. Run the scanner as an
    account that can read through that share.


3. Install
----------
  1. Copy the contents of this folder to C:\AV LAB on the scanner host (the paths in the
     runbook then match). Any other folder works too: the scripts find their own location.
  2. Allow TCP 9898 inbound in Windows Defender Firewall, from the SVM data LIFs only:
       New-NetFirewallRule -DisplayName "FPolicy AV 9898" -Direction Inbound -Protocol TCP `
         -LocalPort 9898 -RemoteAddress <SVM data LIF IPs> -Action Allow
  3. Optional, for real detection beyond EICAR:  .\fpolicy\update_signatures.ps1


4. Start, stop, watch
---------------------
  In a PowerShell window, in the fpolicy folder:
    Set-ExecutionPolicy -Scope Process Bypass      (if scripts are blocked)
    .\start_av_scanner.ps1 -ShareMap 'av_wa_cache=\\cluster2_svm1\c$\av_wa_cache','av_wb_cache=\\cluster2_svm1\c$\av_wb_cache'
    Get-Content .\fpolicy_av.log -Wait -Tail 20     (watch the decisions)
    .\stop_av_scanner.ps1

  -ShareMap has one entry per watched share: <share name as ONTAP reports it>=<UNC path
  of the same folder through the out-of-scope share>. The default is the lab's two cache
  shares. Other options: -Port (9898), -MaxMB (25: larger files are allowed unscanned),
  -Python (path to python.exe).


5. ONTAP configuration (cache SVM)
----------------------------------
  vserver fpolicy policy external-engine create -vserver <svm> -engine-name av_engine -primary-servers <this host IP> -port 9898 -extern-engine-type synchronous -ssl-option no-auth -extern-engine-format xml
  vserver fpolicy policy event create -vserver <svm> -event-name av_open -protocol cifs -file-operations open -filters exclude-directory
  vserver fpolicy policy event create -vserver <svm> -event-name av_close -protocol cifs -file-operations close -filters close-with-modification,exclude-directory
  vserver fpolicy policy create -vserver <svm> -policy-name av_pol -events av_open,av_close -engine av_engine -is-mandatory false
  vserver fpolicy policy scope create -vserver <svm> -policy-name av_pol -shares-to-include <watched shares>
  vserver fpolicy enable -vserver <svm> -policy-name av_pol -sequence-number 1
  vserver fpolicy show-engine -vserver <svm>         (expect: connected)

  -is-mandatory false = fail-open (opens allowed while the scanner is down).
  Use true for fail-closed.


6. Test
-------
  On a client, save this exact line with Notepad to a file on a watched share, close it,
  then open it again: the second open is refused with "Access denied".
    X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
  Turn off real-time antivirus on the test client first, or it removes the file before
  it reaches the share.


7. Differences from the lab run described in the runbook
--------------------------------------------------------
  - File names containing & < > are decoded and scanned like any other file.
  - The __probeN__ file-name diagnostic is off; start fpolicy_av.py with --probe-codes
    to turn it on (lab diagnostics only).
  - The start script takes the share map and port as parameters, and writes clamd.conf
    for whatever folder the kit is in.


Version: 1 Nov 2026
