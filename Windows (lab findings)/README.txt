FlexCache and Antivirus - Lab Findings and an FPolicy + ClamAV Pilot (Windows scanner)
=====================================================================================
Documents to share with the customer: WINDOWS part

Contents
  FlexCache_AV_Windows_Lab_Runbook.html   The document. Open it in any web browser; it works
                                          offline (diagrams included).
  FlexCache_AV_Windows_Lab_Runbook.md     The same content in Markdown (editable source).
  windows-scanner-kit\                     Everything the Windows scanner needs except Python:
                                          the FPolicy server, start/stop scripts, ClamAV 1.5.4
                                          for Windows and the EICAR test signature.
                                          Start with windows-scanner-kit\README.txt.

What it covers
  How antivirus enforcement behaves when SMB clients reach data through ONTAP FlexCache
  volumes (write-around and write-back), compared with the origin, and a lab prototype that
  screens file opens at the cache with ONTAP FPolicy and the open-source ClamAV engine,
  running on a Windows host.

Important
  The FPolicy + ClamAV scanner is a lab prototype, not a NetApp-supported antivirus
  integration. NetApp's supported design for FlexCache is on-access Vscan with a partner
  antivirus engine at the origin, plus scheduled on-demand scans (TR-4743).

Version: 1 Nov 2026
