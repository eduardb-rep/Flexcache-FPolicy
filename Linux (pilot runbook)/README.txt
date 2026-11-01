FlexCache Antivirus Scanning with ONTAP FPolicy and ClamAV - Pilot Runbook (Linux)
=================================================================================
Documents to share with the customer: LINUX part

Contents
  FlexCache_AV_Linux_Pilot_Runbook.html   The document. Open it in any web browser; it works
                                          offline (diagrams included).
  FlexCache_AV_Linux_Pilot_Runbook.md     The same content in Markdown (editable source).
  linux-scanner-kit/                      The install wizards and the FPolicy server. ClamAV and
                                          the other packages are installed by the wizards from
                                          the Ubuntu repositories. Start with
                                          linux-scanner-kit/README.md.

What it covers
  A pilot design for scanning files when SMB clients access data through ONTAP FlexCache
  volumes: Linux scanner hosts (for example Ubuntu on Amazon EC2, next to an FSx for NetApp
  ONTAP cache SVM) receive ONTAP FPolicy notifications, scan files with ClamAV and allow or
  deny each open. Includes prerequisites, installation, operation, the test plan and pilot
  success criteria.

Important
  This is a prototype, not a NetApp-supported antivirus integration. NetApp's supported
  design for FlexCache is on-access Vscan with a partner antivirus engine at the origin,
  plus scheduled on-demand scans (TR-4743).

Version: 1 Nov 2026
