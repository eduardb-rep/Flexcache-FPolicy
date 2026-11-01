# FlexCache and Antivirus - Lab Findings and an FPolicy + ClamAV Pilot (Windows scanner)

**What this document is.** A record of a lab study of how antivirus enforcement behaves when SMB clients
reach data through FlexCache volumes (write-around and write-back), compared with going straight to the
origin. It also covers a pilot that adds content scanning at the cache with ONTAP FPolicy and the
open-source ClamAV engine. It shows what can be achieved and exactly how it was built, so it can serve
as the starting point for a pilot in your environment.

**What it is not.** The FPolicy + ClamAV scanner is a lab prototype, **not a NetApp-supported antivirus
integration**. NetApp's supported design for FlexCache is:

- on-access Vscan with a partner antivirus engine, for clients connected to the origin;
- scheduled on-demand scans at the origin (TR-4743).

A separate document, *FlexCache Antivirus Scanning with ONTAP FPolicy and ClamAV - Pilot Runbook*,
describes a Linux version of the scanner designed for a pilot.

**Lab environment.**

- ONTAP 9.19.1 on two single-node clusters (the "Getting Started with FlexCache" lab).
- A WAN emulator between them: 200 ms round trip, 400 Mbit/s.
- A Windows jumphost that maps the shares and hosts the scanner.
- Built and tested on 28-29 Oct 2026.

---

## 1. Key findings

| # | Test | Result | Meaning |
|---|------|--------|---------|
| 1 | Origin share (`O:`), Vscan on, mandatory scan, no scanner: create/write/close a file | Allowed | Vscan screens *opens*, not writes. There is no scan before a write. |
| 2 | Same share: open an existing file for read | Denied: "A device attached to the system is not functioning." | Mandatory scan blocks reads when no scanner is available. |
| 3 | Write through the write-around cache (`X:`) | Allowed; file lands on the origin | Cache writes reach the origin over the FlexCache protocol, not SMB, so they are never screened there. |
| 4 | Read through the cache (`X:`) a file the origin blocks | **Served** | The origin's Vscan does not protect reads at the cache. |
| 5 | Vscan + mandatory scan enabled on the cache SVM | Still served; ONTAP logged no Vscan event | On-access Vscan does not apply to FlexCache volumes (matches TR-4743 and the KB below). |
| 6 | FPolicy (synchronous) + ClamAV on the cache SVM, EICAR written to `X:\EICAR.txt` | Save allowed; `INFECTED WRITTEN` logged on close (07:28:58); next open denied, "Access denied" (07:29:12) | A custom (not NetApp-supported) way to screen opens at the cache. It works: the infected file is blocked at the cache from the next open. The infected bytes still land on the origin. |

References:

- TR-4743 *FlexCache in ONTAP*, section "Auditing, FPolicy and antivirus scanning": "FlexCache operations are not
  SMB operations, and therefore you must use the on-demand scanning schedule", plus Best Practice 7.
- KB: [On-access scan does not occur when accessing FlexCache volume](https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/On-access_scan_does_not_occur_when_accessing_FlexCache_volume)
- [Vscan file-operations profiles](https://docs.netapp.com/us-en/ontap/antivirus/architecture-concept.html)
- [FlexCache auditing and FPolicy](https://docs.netapp.com/us-en/ontap/flexcache/audit-flexcache-volumes-concept.html)

---

## 2. Topology

```
                       192.168.0.x (data center)        WAN emulator          192.168.2.x (remote office)
                                                        200 ms / 400 Mbit
 JUMPHOST 192.168.0.5 ───────────────┐                       │
  - drives O: P: X: Y:               │                       │
  - ClamAV clamd   127.0.0.1:3310    │                       │
  - FPolicy server 0.0.0.0:9898  <───┼─── FPolicy (TCP 9898) ─┼──── cluster2_svm1 data LIF 192.168.2.132
  - ONTAP AV Connector (installed)   │                       │
                                     │                       │
 cluster1 (origin) mgmt .0.101       │                       │     cluster2 (cache) mgmt .2.102
  cluster1_svm1  data LIF .0.131     │   intercluster        │      cluster2_svm1 data LIF .2.132
   av_wa_origin (20 GB NTFS)  <──────┼── ic_lif1 .0.141 <────┼──> ic_lif1 .2.141 ──  av_wa_cache (10 GB, write-around)
   av_wb_origin (20 GB NTFS)  <──────┼───────────────────────┼─────────────────────  av_wb_cache (10 GB, write-back)
   Vscan ON (fake scanner)           │                       │      FPolicy av_pol ON, Vscan OFF
```

---

## 3. Glossary

| Entity | What it is |
|--------|-----------|
| **Origin volume** | The authoritative copy of the data (`av_wa_origin` and `av_wb_origin` on cluster1). |
| **FlexCache volume** | A sparse cache on another cluster that fills on demand from the origin (`av_wa_cache` and `av_wb_cache` on cluster2). |
| **Write-around** | Default cache mode: a write is forwarded to the origin and acknowledged only after the origin commits it. |
| **Write-back** | Per-cache mode (9.15.1+): the write is committed and acknowledged at the cache, and the dirty data is flushed to the origin later. For SMB that happens when the file is closed, when the file is accessed at the origin or another cache, or through the cache's mtime scrubber. |
| **Intercluster LIF / peering** | Network interfaces and trust relationships (cluster peer and SVM peer) that carry FlexCache traffic between the clusters. |
| **Vscan** | ONTAP's built-in antivirus framework. ONTAP sends scan requests for SMB opens, closes and renames (on-access), or on a schedule (on-demand), to external Windows scanners. |
| **Scanner pool** | List of the Vscan server IPs and privileged users allowed to connect to an SVM. |
| **Mandatory scan** | On-access policy setting: if no scanner is available, file opens that need a scan are denied. |
| **ONTAP AV Connector** | NetApp Windows service (`ontapavc`) that connects a Vscan server to ONTAP. It works only with partner AV engines (Trellix, Trend Micro, Symantec, SentinelOne, OPSWAT and others) through a partner interface. Installed in the lab, but not configured, because no partner engine was available. |
| **FPolicy** | ONTAP's file-access notification framework. With a **synchronous external engine**, ONTAP sends each monitored operation to an external TCP server and waits for an allow or deny answer. Supported on FlexCache volumes over SMB from 9.14.1. |
| **FPolicy server** | Any program that speaks the FPolicy protocol (framed XML over TCP). Here it is `fpolicy_av.py`. |
| **`fpolicy_av.py`** | Python FPolicy server written for this pilot (lab prototype). It receives SMB open and close events from the cache SVM, reads the file through an out-of-scope path (`c$`), sends it to ClamAV and answers ONTAP with allow or deny. |
| **ClamAV / `clamd`** | Open-source antivirus engine (Cisco Talos). `clamd` is its scanning daemon, which accepts data over TCP (the `INSTREAM` command). |
| **EICAR** | Industry-standard, harmless 68-byte test string that every AV engine detects as "infected". |

---

## 4. What was provisioned and how

All ONTAP commands were run in the ONTAP CLI of each cluster (clustershell over SSH).

### 4.1 Intercluster networking and peering
```text
cluster1::> net int create -vserver cluster1 -lif ic_lif1 -address 192.168.0.141 -netmask 255.255.255.0 -home-node cluster1-01 -home-port e0d -service-policy default-intercluster
cluster2::> net int create -vserver cluster2 -lif ic_lif1 -address 192.168.2.141 -netmask 255.255.255.0 -home-node cluster2-01 -home-port e0e -service-policy default-intercluster
cluster1::> cluster peer create -peer-addrs 192.168.2.141 -generate-passphrase -applications snapmirror,flexcache
    # completed on cluster2 with "cluster peer create" (or REST: POST /api/cluster/peers)
cluster2::> vserver peer create -vserver cluster2_svm1 -peer-vserver cluster1_svm1 -peer-cluster cluster1 -applications snapmirror,flexcache
cluster1::> vserver peer accept -vserver cluster1_svm1 -peer-vserver cluster2_svm1
```

### 4.2 Origin volumes and shares (cluster1)
```text
vol create -vserver cluster1_svm1 -volume av_wa_origin -aggregate cluster1_01_SSD_1 -size 20g -security-style ntfs -junction-path /av_wa_origin -space-guarantee none
vol create -vserver cluster1_svm1 -volume av_wb_origin -aggregate cluster1_01_SSD_1 -size 20g -security-style ntfs -junction-path /av_wb_origin -space-guarantee none
vserver cifs share create -vserver cluster1_svm1 -share-name av_wa_origin -path /av_wa_origin
vserver cifs share create -vserver cluster1_svm1 -share-name av_wb_origin -path /av_wb_origin
```

### 4.3 FlexCache volumes and shares (cluster2)
```text
vol flexcache create -vserver cluster2_svm1 -volume av_wa_cache -origin-vserver cluster1_svm1 -origin-volume av_wa_origin -aggr-list cluster2_01_SSD_1 -size 10g -junction-path /av_wa_cache
vol flexcache create -vserver cluster2_svm1 -volume av_wb_cache -origin-vserver cluster1_svm1 -origin-volume av_wb_origin -aggr-list cluster2_01_SSD_1 -size 10g -junction-path /av_wb_cache
set advanced
volume flexcache config modify -vserver cluster2_svm1 -volume av_wb_cache -is-writeback-enabled true
set admin
vserver cifs share create -vserver cluster2_svm1 -share-name av_wa_cache -path /av_wa_cache
vserver cifs share create -vserver cluster2_svm1 -share-name av_wb_cache -path /av_wb_cache
```

### 4.4 Data population
`robocopy` from the jumphost into **both origins** (over the LAN; the caches fill on demand):
`C:\Python311` → `Python311`, `C:\Windows\Web|Media|Help` → `Windows_*`, `C:\Program Files\PuTTY` → `PuTTY`, and the
VSCodium installer → `Installers`. About 11,353 files and 404 MB per origin.

### 4.5 Drive mappings on the jumphost (persistent)
| Drive | Share | Role |
|-------|-------|------|
| `O:` | `\\cluster1_svm1\av_wa_origin` | Origin of the write-around cache |
| `P:` | `\\cluster1_svm1\av_wb_origin` | Origin of the write-back cache |
| `X:` | `\\cluster2_svm1\av_wa_cache` | Write-around cache (across the WAN) |
| `Y:` | `\\cluster2_svm1\av_wb_cache` | Write-back cache (across the WAN) |

### 4.6 ONTAP AV Connector 1.0.7P1 (installed, not configured)

- Installed silently from the MSI inside the NetApp installer. The `ontapavc` service starts
  automatically under a domain account.
- No LIFs are configured and no AV engine is behind it, because no partner engine licence was
  available. The jumphost IP is not in any scanner pool, so the connector does not affect the tests.
- It is kept for a later test with a partner engine (Vscan at the origin, the supported design).

### 4.7 Vscan "no-scanner" configuration
Origin (`cluster1_svm1`), **enabled**:
```text
vserver vscan scanner-pool create -vserver cluster1_svm1 -scanner-pool fake_pool -hostnames 192.168.0.250 -privileged-users "DEMO\Administrator"
vserver vscan scanner-pool apply-policy -vserver cluster1_svm1 -scanner-pool fake_pool -scanner-policy primary
vserver cifs share modify -vserver cluster1_svm1 -share-name c$ -vscan-fileop-profile no-scan
vserver cifs share modify -vserver cluster1_svm1 -share-name cluster1_svm1_ntfs_fc_origin -vscan-fileop-profile no-scan
vserver cifs share modify -vserver cluster1_svm1 -share-name cluster1_svm1_unix_fc_origin -vscan-fileop-profile no-scan
vserver vscan enable -vserver cluster1_svm1
```
The default on-access policy `default_CIFS` was left as is: mandatory scan on, extensions `*`, files with no extension included.
192.168.0.250 is an unused IP, so no scanner ever connects.

Cache (`cluster2_svm1`): same configuration with `fake_pool` = 192.168.2.250 and `c$` set to `no-scan`. Vscan is now
**disabled** there (`vserver vscan disable`) because it had no effect on FlexCache volumes; the pool still exists.

### 4.8 ClamAV 1.5.4 (portable, no install)
| Item | Location |
|------|----------|
| Binaries | `C:\AV LAB\clamav\bin\clamav-1.5.4.win.x64\` (from the GitHub release zip) |
| Config | `C:\AV LAB\clamav\clamd.conf`: `TCPSocket 3310`, `TCPAddr 127.0.0.1`, `StreamMaxLength 100M` |
| Signatures | `C:\AV LAB\clamav\db\lab_eicar.ndb`: one custom EICAR signature (`Lab.EICAR-Test-File`) |
| Log | `C:\AV LAB\clamav\clamd.log` |

The official signature mirrors (`database.clamav.net`) return HTTP 403 from this lab, so only the custom signature is
loaded. ClamAV reports detections as `Lab.EICAR-Test-File.UNOFFICIAL`.

### 4.9 FPolicy on the cache SVM (cluster2)
```text
vserver fpolicy policy external-engine create -vserver cluster2_svm1 -engine-name av_engine -primary-servers 192.168.0.5 -port 9898 -extern-engine-type synchronous -ssl-option no-auth -extern-engine-format xml
vserver fpolicy policy event create -vserver cluster2_svm1 -event-name av_open  -protocol cifs -file-operations open  -filters exclude-directory
vserver fpolicy policy event create -vserver cluster2_svm1 -event-name av_close -protocol cifs -file-operations close -filters close-with-modification,exclude-directory
vserver fpolicy policy create -vserver cluster2_svm1 -policy-name av_pol -events av_open,av_close -engine av_engine -is-mandatory false
vserver fpolicy policy scope create -vserver cluster2_svm1 -policy-name av_pol -shares-to-include av_wa_cache,av_wb_cache
vserver fpolicy enable -vserver cluster2_svm1 -policy-name av_pol -sequence-number 1
```

- The scope covers only the two cache shares. The server reads files through `\\cluster2_svm1\c$\...`, which is out of
  scope, so its own reads do not trigger FPolicy events.
- `-is-mandatory false`: if the server is down, opens are **allowed** (fail-open), so the lab can't lock itself out.

### 4.10 `fpolicy_av.py` (the FPolicy server)
Location: `C:\AV LAB\fpolicy\fpolicy_av.py`. Uses only the Python 3.11 standard library.

How it works:

1. **Framing:** each message is `"` + 4-byte big-endian length + `"` + XML header + `\n\n` + XML body + NUL.
2. **Handshake:** answers `NEGO_REQ` with `NEGO_RESP` (`<HandshakeResp>`, highest common version; ONTAP 9.19.1 negotiates 1.2).
3. **`SCREEN_REQ` `SMB_OPEN`:**
    - Maps `\\CLUSTER2_SVM1\<share>\<path>` to `\\cluster2_svm1\c$\<share>\<path>`.
    - Scans the file with clamd (`INSTREAM`), or with a built-in EICAR matcher if clamd is down.
    - Answers ONTAP with `<FscreenResp><ReqId/><ReqType/><NotfResp>N</NotfResp></FscreenResp>`.
4. **`SCREEN_REQ` `SMB_CLOSE`** (modified files only): allows immediately, rescans in the background and logs
   `INFECTED WRITTEN` when it finds something.
5. **Verdict cache:** results are cached by path, size and mtime. Files over 25 MB are skipped (allowed and logged as `skipped-too-large`).

`NotfResp` codes, found by testing against 9.19.1:

| Code | Meaning |
|------|---------|
| `1` | Allow |
| `2` | Deny (client sees "Access denied") |
| `0` | Invalid: ONTAP sends a FATAL alert and drops the connection |

Logs:

| File | Content |
|------|---------|
| `C:\AV LAB\fpolicy\fpolicy_av.log` | `ALLOW`, `DENY`, `INFECTED WRITTEN`, connects and disconnects |
| `C:\AV LAB\fpolicy\fpolicy_av_raw.log` | The first 10 raw `SCREEN_REQ` XML bodies |

Options: `--allow-code`, `--deny-code`, `--max-mb`, `--clamd-host`, `--clamd-port`, `--port`, `--raw-dump`.
Diagnostics: with `--probe-codes`, a file whose name contains `__probeN__` makes the server answer with code `N`. It was used once to find the codes above; in the scanner kit it is off by default (see section 7).

Public reference implementations consulted: Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns,
YhunerFSY/ontap-fpolicy-aws-integration, AhmedRamadanAbdElghany/fpolicyServer and Esraayasser/Netapp-Fpolicy-External-Server.

---

## 5. Operating the scanner stack

| Task | How |
|------|-----|
| Start (safe to re-run) | `powershell -File "C:\AV LAB\fpolicy\start_av_scanner.ps1"` |
| Force ONTAP to reconnect | `cluster2::> vserver fpolicy engine-connect -node cluster2-01 -vserver cluster2_svm1 -policy-name av_pol -server 192.168.0.5` |
| Connection status | `cluster2::> vserver fpolicy show-engine -vserver cluster2_svm1` |
| Watch decisions live | `Get-Content 'C:\AV LAB\fpolicy\fpolicy_av.log' -Wait -Tail 20` |
| Stop the FPolicy server | `Get-NetTCPConnection -LocalPort 9898 -State Listen \| % { Stop-Process -Id $_.OwningProcess }` |
| Stop clamd | `Get-NetTCPConnection -LocalPort 3310 -State Listen \| % { Stop-Process -Id $_.OwningProcess }` |
| Pause screening (keep config) | `cluster2::> vserver fpolicy disable -vserver cluster2_svm1 -policy-name av_pol` |
| Resume screening | `cluster2::> vserver fpolicy enable -vserver cluster2_svm1 -policy-name av_pol -sequence-number 1` |
| ONTAP-side FPolicy and Vscan events | `event log show -message-name *fpolicy*` / `*vscan*` |

---

## 6. Test procedures and results

EICAR string (type it exactly, on one line):
`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

| ID | Steps | Expected with this configuration | Lab result |
|----|-------|----------------------------------|------------|
| FP-1 | Notepad → save the EICAR string as `X:\eicar_wa.txt` → close | Save succeeds; the log shows `INFECTED WRITTEN` | Observed with `X:\EICAR.txt` (29 Oct, 07:28:58) |
| FP-2 | Open `X:\eicar_wa.txt` again | "Access denied"; the log shows `DENY SMB_OPEN ... Lab.EICAR-Test-File` | Observed (07:29:12, answered in 1.2 s) |
| FP-3 | Repeat FP-1 and FP-2 on `Y:` (write-back) | Same result at the cache | Pilot step, not run yet |
| FP-4 | After FP-3, list `P:\` (do not open the file) | The file is on the origin: SMB close flushes the dirty data, and the cache scan does **not** stop the flush | Pilot step, not run yet (expected from NetApp documentation) |
| FP-5 | Open the EICAR file on `O:` or `P:` | Blocked by the origin's no-scanner Vscan (not a detection, just "no scanner") | Same mechanism observed with other files (findings 1 and 2) |
| FP-6 | Open any clean file on `X:` or `Y:` | Opens; the log shows `ALLOW ... clean via clamav` | Observed on `X:` (0.8-4.5 s per open) |
| FP-7 | Stop the FPolicy server, then open the EICAR file on `X:` | **Opens** (fail-open, because `-is-mandatory false`) | Pilot step, not run yet |
| FP-8 | Same as FP-7 with `vserver fpolicy policy modify -vserver cluster2_svm1 -policy-name av_pol -is-mandatory true` | Denied while the server is down (fail-closed) | Pilot step, not run yet |

Notes:

- **Latency:** each screened open costs 0.8-4.5 s, because the scanner is on the far side of the WAN from cluster2. Browsing `X:` and `Y:` in Explorer is slow.
- **Deleting an infected file** through `X:` or `Y:` is also denied, because a delete requires an open. Delete it through `\\cluster2_svm1\c$\av_wa_cache\...` or `...\av_wb_cache\...`.
- **Reopening:** close Notepad first. Otherwise the Windows SMB client may serve the file from its own cache.
- **Packet captures (planned):** SMB2 between the jumphost and 192.168.2.132, FPolicy on TCP 9898, and FlexCache traffic between the two `ic_lif1` interfaces.

---

## 7. Limitations and security notes

- **Not a NetApp-supported antivirus integration.** `fpolicy_av.py` is a lab prototype. The supported design
  for FlexCache is on-access Vscan for clients connected to the origin plus scheduled **on-demand** scans at
  the origin (TR-4743, Best Practice 7); both need a partner AV engine.
- **Write path:** content is scanned after it is written (at close), so infected bytes reach the origin and
  only the next open at the cache is blocked. Nothing is quarantined or deleted.
- **Performance:**
    - Each screened open costs 0.8-4.5 s here, because the scanner is across the 200 ms WAN from the cache.
    - Screening opens on a cache forces path lookups at the origin.
    - NetApp advises against monitoring read and getattr operations on FlexCache volumes, for performance reasons.
- **Large files:** files over 25 MB are allowed without a scan in this build.
- **Fail-open:** with `-is-mandatory false`, an open is allowed unscanned while the server is down. The same
  happens when the server doesn't answer within ONTAP's 20 s timeout.
- **Privileges and exposure (acceptable in an isolated lab only):**
    - The scanner reads files through the `c$` administrative share as a domain administrator.
    - The FPolicy channel (TCP 9898) is unauthenticated plain text.
    - The jumphost firewall is off.
- **Diagnostic codes:** the `__probeN__` file-name diagnostic lets a file name choose the answer. It is off by default in the scanner kit and must stay off beyond the lab.
- **Signatures:** ClamAV has only the custom EICAR signature (the official database wasn't reachable from
  the lab), so it detects nothing else.
- **Scale:** a single scanner with an in-memory verdict cache.

The Linux pilot design (separate pilot runbook) addresses most of these:

- the scanners run next to the cache;
- files are read through a read-only `scan$` share as a dedicated service account;
- large files are scanned in the background;
- the scanner always answers within a deadline, and can fail closed;
- a verdict cache can be shared by several scanners;
- diagnostic codes are off by default.

---

## 8. Rollback and teardown

```text
# cache side (cluster2)
vserver fpolicy disable -vserver cluster2_svm1 -policy-name av_pol
vserver fpolicy policy scope delete -vserver cluster2_svm1 -policy-name av_pol
vserver fpolicy policy delete -vserver cluster2_svm1 -policy-name av_pol
vserver fpolicy policy event delete -vserver cluster2_svm1 -event-name av_open
vserver fpolicy policy event delete -vserver cluster2_svm1 -event-name av_close
vserver fpolicy policy external-engine delete -vserver cluster2_svm1 -engine-name av_engine
vserver vscan scanner-pool apply-policy -vserver cluster2_svm1 -scanner-pool fake_pool -scanner-policy idle
vserver vscan scanner-pool delete -vserver cluster2_svm1 -scanner-pool fake_pool

# origin side (cluster1)
vserver vscan disable -vserver cluster1_svm1
vserver vscan scanner-pool apply-policy -vserver cluster1_svm1 -scanner-pool fake_pool -scanner-policy idle
vserver vscan scanner-pool delete -vserver cluster1_svm1 -scanner-pool fake_pool
vserver cifs share modify -vserver cluster1_svm1 -share-name <share> -vscan-fileop-profile standard   # c$ and the two pre-existing lab shares
```
Jumphost: stop both processes (section 5). Uninstall "ONTAP AV Connector" from Programs and Features if no longer needed.

---

## 9. Components on the scanner host

The `windows-scanner-kit` folder delivered with this document holds everything below except Python
(see its `README.txt`). Copied to `C:\AV LAB`, its paths match this runbook.

| Path | Purpose |
|------|---------|
| `C:\AV LAB\clamav\bin\clamav-1.5.4.win.x64\` | ClamAV 1.5.4 for Windows x64 (runtime files of the official release) |
| `C:\AV LAB\clamav\db\lab_eicar.ndb` | Test signature: detects the EICAR string anywhere in a file |
| `C:\AV LAB\clamav\clamd.conf`, `clamd.log` | Written by the start script and by `clamd` |
| `C:\AV LAB\fpolicy\fpolicy_av.py` | FPolicy AV server |
| `C:\AV LAB\fpolicy\start_av_scanner.ps1`, `stop_av_scanner.ps1` | Start and stop `clamd` and the FPolicy server |
| `C:\AV LAB\fpolicy\update_signatures.ps1` | Optional: downloads the official ClamAV signatures |
| `C:\AV LAB\fpolicy\fpolicy_av*.log` | Decision log and raw request dump |

The ONTAP AV Connector used in the lab isn't part of the kit. It is available from the NetApp Support
Site and is only needed with a partner antivirus engine.

---

## 10. Detailed data-path schemas

Built from this lab's live state on 29 Oct 2026. Sources:

- ONTAP `show` output: SMB sessions, the FPolicy engine and connection, and the Vscan pool.
- The jumphost TCP table and routing table.
- The raw FPolicy requests in `fpolicy_av_raw.log`, and the decision log of the EICAR test.

Steps marked **documented** come from NetApp documentation (TR-4743, the FlexCache write-back architecture page, and the
FlexCache ports KB) and could not be observed directly in the lab.

### 10.1 Connection map

<!--SVG:connection_map-->

| # | Socket (observed unless marked) | Protocol | Carries | Encrypted on the wire | Visible in a capture |
|---|------|----------|---------|-----------|----------------------|
| 1 | `192.168.0.5:56607` → `192.168.2.132:445` | SMB 3.1.1, Kerberos, session `10179542532740874242` | Everything on `X:` and `Y:`, plus the scanner's `c$` reads (same TCP connection, separate tree connect) | No (`Is Session Signed: false`, `unencrypted`) | Fully decodable SMB2 |
| 2 | `192.168.0.5:56035` → `192.168.0.131:445` | SMB 3.1.1, Kerberos | Everything on `O:` and `P:` | No | Fully decodable SMB2 |
| 3 | `192.168.2.132:53351` → `192.168.0.5:9898` | FPolicy external engine, XML, synchronous, `ssl-option no-auth` | NEGO, SCREEN_REQ/RESP, KEEP_ALIVE, ALERT | No | Plain XML ("Follow TCP stream") |
| 4 | `127.0.0.1:<ephemeral>` → `127.0.0.1:3310` | clamd `INSTREAM` | File bytes and verdict | No | Only with a loopback capture (Npcap loopback adapter) |
| 5 | `192.168.2.141` ↔ `192.168.0.141` (documented) | RAL: TCP 11104 control sessions, 11105 data | Inode fetch, block reads, remote writes, XLD, delegation revokes, write-back flush | Yes (cluster peering TLS) | Headers and timing only |
| 6 | Jumphost → `192.168.0.253` | DNS 53, Kerberos 88 | Name lookup for `cluster*_svm1`, tickets for `cifs/...` | Kerberos tickets are encrypted | Decodable headers |
| 7 | `fake_pool` 192.168.0.250 → `192.168.0.131` (never happens) | Vscan (a scanner connects to the SVM) | Would carry scan requests | – | Nothing; that's why mandatory scan denies |

Every packet between `192.168.0.x` and `192.168.2.x` crosses the WAN emulator. The jumphost route is
`192.168.2.0/24 via 192.168.0.2`. One FPolicy screening therefore costs at least two WAN round trips:
one for SCREEN_REQ/RESP and one or more for the scanner's own SMB reads back to the cache.

**Jumphost process and socket inventory** (live, `Get-NetTCPConnection` / `Win32_Process`, 29 Oct 09:15)

| Process | PID | Socket | State | Notes |
|---------|-----|--------|-------|-------|
| `python.exe fpolicy_av.py` | 3516 | `0.0.0.0:9898` | LISTEN | Main thread: `listen(16)` and `accept()`. Reachable from any host, because the Windows firewall is off and FPolicy `no-auth` has no authentication. |
| | | `192.168.0.5:9898` ↔ `192.168.2.132:53351` | ESTABLISHED | The only FPolicy connection. Opened by ONTAP (connected since 28 Oct 15:00:50). One reader thread, 600 s read timeout, keep-alive every 2 min. |
| | | `127.0.0.1:<ephemeral>` → `127.0.0.1:3310` | short-lived | One connection per scan: 15 s timeout, 64 KiB `INSTREAM` chunks, closed after the reply. |
| | | none (file I/O) | – | `os.stat` / `open` on `\\cluster2_svm1\c$\...` go through the kernel SMB redirector. |
| `clamd.exe` | 5512 | `127.0.0.1:3310` | LISTEN | Loopback only. `MaxThreads 16`, `StreamMaxLength 100M`, database self-check every 600 s. |
| System (SMB redirector) | 4 | `192.168.0.5:56607` → `192.168.2.132:445` | ESTABLISHED | `X:`, `Y:` and the scanner's `c$` reads (shared connection, separate tree connect). |
| | | `192.168.0.5:56035` → `192.168.0.131:445` | ESTABLISHED | `O:`, `P:` |
| `ontapavc.exe` (AV Connector) | 7084 | none | – | Not configured. Once LIFs are added it would use HTTPS 443 to the management LIF (REST polling every 60 s) and SMB 445 to the data LIFs. |
| DNS client | – | UDP → `192.168.0.253:53` | on demand | Resolves `cluster2_svm1` for the UNC path. |

### 10.2 Session and channel setup (happens before any file operation)

```mermaid
sequenceDiagram
    autonumber
    box rgb(234,242,252) Jumphost 192.168.0.5
        participant R as SMB redirector
        participant PY as fpolicy_av.py :9898
        participant CL as clamd :3310
    end
    participant DC as DC1 192.168.0.253
    box rgb(255,244,229) cluster2 - cache
        participant S as cluster2_svm1 SMB :445
        participant F as FPolicy engine av_pol
        participant IC2 as ic_lif1 .2.141
    end
    box rgb(233,247,236) cluster1 - origin
        participant IC1 as ic_lif1 .0.141
    end
    rect rgb(245,245,245)
        Note over IC2,IC1: Done once: cluster peer + SVM peer (TLS, ports 11104/11105, documented)
        IC2->>IC1: RAL sessions between intercluster LIFs (crosses WAN)
    end
    rect rgb(240,248,255)
        Note over CL: clamd.conf: TCPSocket 3310, TCPAddr 127.0.0.1, StreamMaxLength 100M
        CL->>CL: load db\lab_eicar.ndb (1 signature), listen 127.0.0.1:3310
        PY->>PY: bind 0.0.0.0:9898, share map av_wa_cache, av_wb_cache to \\cluster2_svm1\c$\...
    end
    rect rgb(255,250,240)
        Note over R,S: First access to X: or Y:
        R->>DC: DNS A? cluster2_svm1.demo.netapp.com (UDP 53)
        DC-->>R: 192.168.2.132
        R->>DC: Kerberos TGS-REQ for cifs/cluster2_svm1.demo.netapp.com (88)
        DC-->>R: service ticket (AES256)
        R->>S: TCP SYN to 445 via 192.168.0.2 (crosses WAN)
        R->>S: SMB2 NEGOTIATE (dialects 2.0.2 to 3.1.1, preauth SHA-512)
        S-->>R: dialect 3.1.1, large MTU
        R->>S: SMB2 SESSION_SETUP (SPNEGO, Kerberos AP-REQ)
        S->>S: validate ticket with SVM machine key, map DEMO\Administrator to UNIX root (uid 0)
        S-->>R: STATUS_SUCCESS, SessionId 10179542532740874242, not signed, not encrypted
        R->>S: SMB2 TREE_CONNECT \\cluster2_svm1\av_wa_cache, av_wb_cache (and c$ for the scanner)
        S-->>R: TreeIds
    end
    rect rgb(240,255,240)
        Note over S,PY: FPolicy channel - opened by ONTAP when av_pol is enabled or on engine-connect
        F->>PY: TCP 192.168.2.132:53351 to 192.168.0.5:9898 (crosses WAN)
        F->>PY: NEGO_REQ SessionId 5d02797b..., PolicyName av_pol, Vers 1.0 1.1 1.2 2.0 3.0
        PY-->>F: NEGO_RESP ProtVersion 1.2
        Note over F: show-engine shows connected since 28 Oct 15:00:50
        loop every 2 min
            F->>PY: KEEP_ALIVE (no reply expected)
        end
    end
```

### 10.3 Open (read) through the write-around cache `X:`

Notepad opening `X:\EICAR.txt`. The field values are from the real request captured at 07:28:36 (ReqId 3075).

```mermaid
sequenceDiagram
    autonumber
    box rgb(234,242,252) Jumphost 192.168.0.5
        participant U as Notepad / Explorer
        participant R as SMB redirector :56607
        participant PY as fpolicy_av.py :9898
        participant CL as clamd :3310
    end
    box rgb(255,244,229) cluster2 - cache SVM cluster2_svm1
        participant S as SMB server .2.132:445
        participant F as FPolicy engine av_pol
        participant C as av_wa_cache WAFL + RAL + RIM
    end
    box rgb(233,247,236) cluster1 - origin
        participant O as av_wa_origin RAL + REM
    end
    U->>R: CreateFile X:\EICAR.txt GENERIC_READ
    R->>S: SMB2 CREATE EICAR.txt, FILE_OPEN, access 0x120089, share R+W, options 0x60, lease request (WAN one-way about 100 ms)
    S->>C: lookup path, load inode
    alt inode cached and RIM data delegation still valid
        C-->>S: attributes from cache, no origin contact
    else not cached, or delegation revoked by a write
        C->>O: RAL remote retrieve inode (TCP 11104/11105, TLS, WAN)
        O->>O: read inode, check locks, add delegation to REM
        O-->>C: inode + attributes
        C->>C: store inode, add RIM entry
        C-->>S: attributes
    end
    S->>F: open event: share av_wa_cache in scope, event av_open, not a directory
    Note over S,F: SMB2 CREATE is held - synchronous engine, cancel 20 s, abort 40 s, mandatory false
    F->>PY: SCREEN_REQ ReqId 3075 SMB_OPEN, DisplayPath \\CLUSTER2_SVM1\av_wa_cache\EICAR.txt, FileSize, OpenAccmode 131209, OpenSharemode 3, OpenOptions 96
    PY->>PY: decode frame, hand to worker thread, map to \\cluster2_svm1\c$\av_wa_cache\EICAR.txt
    PY->>R: os.stat on the UNC path
    R->>S: SMB2 CREATE (read attributes) + QUERY_INFO + CLOSE on tree c$, same TCP 56607
    Note over S: c$ is outside the av_pol scope and its Vscan profile is no-scan, so no new SCREEN_REQ (no recursion)
    S-->>R: size + mtime
    R-->>PY: stat result
    alt verdict cache hit - same path, size, mtime
        PY->>PY: reuse verdict - observed 0.8 to 1.6 s end to end
    else cache miss
        PY->>R: open + read up to 25 MB
        R->>S: SMB2 CREATE + READ (up to 1 MB each, large MTU) + CLOSE on c$
        opt blocks not cached
            S->>C: read
            C->>O: RAL remote read (TCP 11105, WAN)
            O-->>C: data blocks
            C->>C: write blocks into the cache
        end
        S-->>R: file data
        R-->>PY: bytes
        PY->>CL: new TCP connect, zINSTREAM\0, chunks of 4-byte length + data (64 KiB), 4 zero bytes
        CL-->>PY: stream OK, or stream Lab.EICAR-Test-File.UNOFFICIAL FOUND
        PY->>PY: store verdict - observed 2.4 to 4.5 s end to end
    end
    alt clean
        PY-->>F: SCREEN_RESP ReqId 3075, NotfResp 1 = ALLOW
        F-->>S: continue
        S-->>R: SMB2 CREATE STATUS_SUCCESS, FileId, lease
        R-->>U: file handle
        U->>R: ReadFile
        R->>S: SMB2 READ
        S->>C: serve from cache (RIM valid)
        S-->>R: data
        U->>R: CloseHandle
        R->>S: SMB2 CLOSE
        Note over S,F: close without modification - av_close only fires on close-with-modification
        S-->>R: CLOSE ok
    else infected
        PY-->>F: SCREEN_RESP NotfResp 2 = DENY
        F-->>S: deny
        S-->>R: SMB2 CREATE STATUS_ACCESS_DENIED 0xC0000022
        R-->>U: ERROR_ACCESS_DENIED (5) - Access is denied
    end
    opt server down, disconnected, or no reply within 20 s
        F-->>S: mandatory false - operation proceeds unscanned (fail-open)
    end
```

| Step | Detail |
|------|--------|
| CREATE held | ONTAP doesn't answer the client's CREATE until the FPolicy server responds or the request times out. The client waits the whole time, including two WAN crossings for FPolicy and the scanner's own SMB round trips. |
| Why the screen request carries `FileSize` | ONTAP resolves the inode first (from the cache, or through RAL from the origin), then builds the notification. |
| Scanner path | The server never reads through `av_wa_cache` itself. It reads through `c$`, which is out of scope, so its reads are never screened. |
| Verdict cache | Key = (path, size, mtime). Notepad's save changes size and mtime, so the next open rescans. A cached verdict still costs one stat round trip. |
| Origin contact on a clean cached read | None if the RIM data delegation is still valid (documented, TR-4743 "File cached and valid"). |

### 10.4 Write through the write-around cache `X:`

This is the lab's EICAR test, as it ran on 29 Oct (times from `fpolicy_av.log`).

```mermaid
sequenceDiagram
    autonumber
    box rgb(234,242,252) Jumphost 192.168.0.5
        participant U as Explorer / Notepad
        participant R as SMB redirector :56607
        participant PY as fpolicy_av.py :9898
        participant CL as clamd :3310
    end
    box rgb(255,244,229) cluster2 - cache SVM cluster2_svm1
        participant S as SMB server .2.132:445
        participant F as FPolicy engine av_pol
        participant C as av_wa_cache WAFL + RAL
    end
    box rgb(233,247,236) cluster1 - origin
        participant O as av_wa_origin RAL + REM
        participant V as Vscan cluster1_svm1
    end
    rect rgb(248,248,248)
        Note over U,O: A. Explorer - New Text Document
        U->>R: New, Text Document
        R->>S: SMB2 CREATE New Text Document.txt, FILE_CREATE
        Note over S,F: FPolicy ReqType SMB_CREAT - av_pol monitors only open + close, so not screened
        S->>C: create on a FlexCache directory
        C->>O: RAL remote create (write-around, TCP 11105, WAN)
        O-->>C: new inode committed at origin
        C-->>S: ok
        S-->>R: CREATE ok
        R->>S: re-open (07:28:00 SMB_OPEN, access 393631, 0 bytes)
        S->>F: screen
        F->>PY: SCREEN_REQ SMB_OPEN
        PY-->>F: NotfResp 1 (clean, 2.4 s)
        R->>S: SMB2 CLOSE
        S->>F: close-with-modification
        F->>PY: SCREEN_REQ SMB_CLOSE, RdBytes 0, WrBytes 0 (07:28:08)
        PY-->>F: NotfResp 1 at once, background scan clean
    end
    rect rgb(248,248,248)
        Note over U,O: B. Rename to EICAR.txt
        R->>S: SMB2 CREATE with DELETE + READ_ATTRIBUTES (07:28:17 SMB_OPEN, access 65664)
        S->>F: screen
        F->>PY: SCREEN_REQ
        PY-->>F: NotfResp 1 (verdict cached)
        R->>S: SMB2 SET_INFO FileRenameInformation EICAR.txt
        S->>C: rename
        C->>O: RAL remote rename (write-around)
        O-->>C: ok
    end
    rect rgb(255,245,245)
        Note over U,O: C. Notepad opens EICAR.txt, pastes EICAR, saves
        R->>S: SMB2 CREATE (07:28:36 GENERIC_READ, 0 bytes) - screened clean, 3.1 s
        R->>S: SMB2 CREATE for the save (07:28:48 SMB_OPEN) - allowed from the verdict cache, still 0 bytes
        U->>R: WriteFile 70 bytes
        R->>S: SMB2 WRITE offset 0, length 70 (+ SET_INFO end of file / times)
        S->>C: write on a FlexCache inode
        C->>O: RAL remote write (TCP 11105, TLS, WAN)
        O->>O: WAFL write to av_wa_origin, NVRAM commit
        O->>O: REM lookup - revoke data delegations for EICAR.txt held by caches (av_wa_cache included)
        Note over O,V: No SMB at the origin, so Vscan is never asked - the infected bytes are now stored on av_wa_origin
        O-->>C: write committed
        C-->>S: ok
        S-->>R: SMB2 WRITE STATUS_SUCCESS (client waited for both WAN hops)
        U->>R: CloseHandle
        R->>S: SMB2 CLOSE
        S->>F: close-with-modification
        F->>PY: SCREEN_REQ SMB_CLOSE, WrBytes 70
        PY-->>F: NotfResp 1 at once (a close can't usefully be denied)
        F-->>S: continue
        S-->>R: CLOSE ok
    end
    rect rgb(255,235,235)
        Note over PY,O: D. Background rescan after close
        PY->>R: stat + read via c$
        R->>S: SMB2 CREATE/READ/CLOSE on c$
        S->>C: read - cache copy invalid (delegation revoked)
        C->>O: RAL remote read
        O-->>C: 70 bytes
        S-->>R: data
        PY->>CL: INSTREAM 70 bytes
        CL-->>PY: Lab.EICAR-Test-File.UNOFFICIAL FOUND
        PY->>PY: log INFECTED WRITTEN (07:28:58), cache verdict - no remediation
    end
    rect rgb(255,235,235)
        Note over U,S: E. Next open (07:29:12)
        R->>S: SMB2 CREATE EICAR.txt
        S->>F: screen
        F->>PY: SCREEN_REQ SMB_OPEN
        PY->>R: stat via c$ - same size + mtime, verdict cache hit
        PY-->>F: NotfResp 2 = DENY (1.2 s)
        S-->>R: STATUS_ACCESS_DENIED
        R-->>U: Access is denied
    end
```

### 10.5 Write through the write-back cache `Y:`

```mermaid
sequenceDiagram
    autonumber
    box rgb(234,242,252) Jumphost 192.168.0.5
        participant U as Notepad
        participant R as SMB redirector :56607
        participant PY as fpolicy_av.py :9898
        participant CL as clamd :3310
    end
    box rgb(255,244,229) cluster2 - cache SVM cluster2_svm1
        participant S as SMB server .2.132:445
        participant F as FPolicy engine av_pol
        participant C as av_wb_cache WAFL + RAL + DDRS
    end
    box rgb(233,247,236) cluster1 - origin
        participant O as av_wb_origin RAL + REM
        participant OS as cluster1_svm1 SMB + Vscan
    end
    U->>R: CreateFile Y:\eicar_wb.txt for write
    R->>S: SMB2 CREATE (write access)
    S->>F: SMB_OPEN screened as in 10.3 - new or empty file is clean
    F->>PY: SCREEN_REQ
    PY-->>F: NotfResp 1
    S->>C: write intent on FlexCache inode
    alt cache already holds the XLD for this file
        C-->>S: grant write lock locally
    else no XLD (documented)
        C->>O: RAL request exclusive lock delegation XLD (TCP 11104/11105, WAN)
        O->>O: another XLD outstanding? (only one cache here, so no) - otherwise recall it and wait for that cache to flush
        O-->>C: XLD granted - data delegations elsewhere revoked
        C-->>S: grant write lock
    end
    S-->>R: CREATE ok - no write oplock or lease (not supported on write-back caches, documented)
    U->>R: WriteFile EICAR bytes
    R->>S: SMB2 WRITE
    S->>C: commit locally - NVRAM + WAFL on cluster2, track in a dirty data record (about 20 MB each)
    Note over C,O: No origin round trip. Over 2 records (about 40 MB) flushing starts during the write
    S-->>R: SMB2 WRITE ok (cache-local ack, the client still crosses the WAN to reach the cache in this lab)
    U->>R: CloseHandle
    R->>S: SMB2 CLOSE
    par SMB close flushes dirty data (documented, stateful protocol)
        C->>O: RAL write-back of the dirty data (TCP 11105, WAN)
        O->>O: commit to av_wb_origin - no SMB, so no Vscan
        O-->>C: flushed
    and FPolicy close screening
        S->>F: close-with-modification
        F->>PY: SCREEN_REQ SMB_CLOSE
        PY-->>F: NotfResp 1 at once
    end
    S-->>R: CLOSE ok
    PY->>R: background stat + read via c$ (cache holds current data)
    R->>S: SMB2 CREATE/READ/CLOSE on c$
    S-->>R: data
    PY->>CL: INSTREAM
    CL-->>PY: FOUND
    PY->>PY: log INFECTED WRITTEN - next open on Y: is denied
    rect rgb(255,240,240)
        Note over OS,O: Later - someone opens the file on P: (origin)
        OS->>O: open eicar_wb.txt
        opt XLD still held by av_wb_cache
            O->>C: recall XLD
            C->>O: flush remaining dirty data
            C-->>O: XLD released
        end
        OS->>OS: Vscan on-access - mandatory, no scanner connected
        OS-->>OS: denied - client sees ERROR_GEN_FAILURE 31 (10.6)
    end
    Note over C,O: Scrubbers (documented) - cache mtime scrubber every 5 min flushes files idle 2 min, origin mtime scrubber every 5 min recalls delegations idle 15 min
```

### 10.6 Open on the origin `O:` or `P:` (Vscan, no scanner)

```mermaid
sequenceDiagram
    autonumber
    box rgb(234,242,252) Jumphost 192.168.0.5
        participant U as App
        participant R as SMB redirector :56035
    end
    box rgb(233,247,236) cluster1 - origin SVM cluster1_svm1
        participant S as SMB server .0.131:445
        participant V as Vscan - policy default_CIFS
        participant P as scanner pool fake_pool 192.168.0.250
        participant W as av_wa_origin / av_wb_origin
    end
    U->>R: open O:\HOLA FROM CACHE\Test.txt for read
    R->>S: SMB2 CREATE read access (LAN, no WAN)
    S->>W: lookup inode
    opt write-back file with an XLD held by the cache
        W->>W: recall XLD, cache flushes dirty data first (see 10.5)
    end
    S->>V: share av_wa_origin profile standard, open needs a scan, extension * included
    V->>P: any connected Vscan server?
    P-->>V: none - 192.168.0.250 never connected
    V-->>S: scan-mandatory on - fail the open
    S->>S: EMS Nblade.vscanNoScannerConn (logged once, 28 Oct 12:27:23)
    S-->>R: CREATE error (observed about 16 ms)
    R-->>U: ERROR_GEN_FAILURE (31) - A device attached to the system is not functioning
    rect rgb(245,255,245)
        Note over U,W: Write-only access is not blocked
        R->>S: SMB2 CREATE new file or append (no read access)
        S->>V: no scan needed to open for write
        S-->>R: CREATE ok
        R->>S: SMB2 WRITE + CLOSE
        S->>V: standard profile - scan requested on close of a modified file
        V-->>S: no scanner - close still completes
        S-->>R: CLOSE ok - the next read open is denied
    end
    Note over S,W: Writes arriving from a cache over RAL never pass through S or V, so they're never screened here
    Note over R,S: \\cluster1_svm1\c$ has profile no-scan - bypasses Vscan entirely
```

### 10.7 Message formats, decoded fields, timers and observed timings

**FPolicy frame (TCP 9898, both directions)**

| Bytes | Content |
|-------|---------|
| 1 | `"` (0x22) |
| 4 | Payload length, big-endian |
| 1 | `"` (0x22) |
| n | `<?xml version="1.0"?><Header><NotfType>…</NotfType><ContentLen>…</ContentLen><DataFormat>XML</DataFormat></Header>` |
| 2 | `\n\n` separator |
| m | `<?xml version="1.0"?>` + body XML (`ContentLen` = m) |
| 1 | NUL terminator |

**Message types seen in this lab**

| Type | Direction | Key fields |
|------|-----------|------------|
| `NEGO_REQ` | ONTAP → server | `SessionId`, `VsUUID`, `PolicyName` = `av_pol`, `Vers` 1.0 1.1 1.2 2.0 3.0 |
| `NEGO_RESP` | server → ONTAP | `HandshakeResp`: same `SessionId`, `VsUUID`, `PolicyName`, `ProtVersion` = 1.2 |
| `SCREEN_REQ` | ONTAP → server | `FscreenReq`: `ReqId`, `ReqType` (`SMB_OPEN`, `SMB_CLOSE`), `NotfInfo` |
| `SCREEN_RESP` | server → ONTAP | `FscreenResp`: `ReqId`, `ReqType`, `NotfResp` (1 = allow, 2 = deny, 0 = invalid, which ONTAP treats as fatal) |
| `KEEP_ALIVE` | ONTAP → server | Every 2 min, no reply |
| `ALERT_MSG` | ONTAP → server | Seen once: `FATAL` "The screen response message received from the FPolicy server is not valid." (the `NotfResp 0` probe) |

**Real SCREEN_REQ (Notepad opening `X:\EICAR.txt`, 07:28:36)**

```xml
<FscreenReq>
  <ReqId>3075</ReqId>
  <ReqType>SMB_OPEN</ReqType>
  <NotfInfo><SmbOpenReq>
    <CommonInfo>
      <ProtCommonInfo>
        <ClientIp>192.168.0.5</ClientIp>
        <GenerationTime>1793258915717898</GenerationTime>
        <UsrIdType>MAPPED_ID</UsrIdType>
        <UsrContext><MappedId><Uid>0</Uid><WinSid>S-1-5-21-4254325344-3421351856-2746113450-500</WinSid></MappedId></UsrContext>
        <FileOwner><WinSid>S-1-5-32-544</WinSid></FileOwner>
        <AccessPath>
          <Path><PathNameType>WIN_NAME</PathNameType><PathName>\EICAR.txt</PathName></Path>
          <Path><PathNameType>UNIX_NAME</PathNameType><PathName>/EICAR.txt</PathName></Path>
        </AccessPath>
        <VolMsid>2160101725</VolMsid>
        <FileSize>0</FileSize><NumHardLnk>1</NumHardLnk><IsOfflineAttr>0</IsOfflineAttr>
        <FileType>FILE</FileType><IsSparse>0</IsSparse><IsDense>0</IsDense>
      </ProtCommonInfo>
      <DisplayPath>\\CLUSTER2_SVM1\av_wa_cache\EICAR.txt</DisplayPath>
      <ProtVer><MajorNum>3</MajorNum><MinorNum>1</MinorNum></ProtVer>
    </CommonInfo>
    <OpenAccmode>131209</OpenAccmode>
    <OpenSharemode>3</OpenSharemode>
    <OpenOptions>96</OpenOptions>
  </SmbOpenReq></NotfInfo>
</FscreenReq>
```

**Decoded fields**

| Field | Value | Meaning |
|-------|-------|---------|
| `UsrContext` | `Uid 0`, SID `…-500` | `DEMO\Administrator`, name-mapped to UNIX `root` (matches `vserver cifs session show`) |
| `FileOwner` | `S-1-5-32-544` | `BUILTIN\Administrators` |
| `VolMsid` | `2160101725` | MSID of `av_wa_cache` |
| `ProtVer` | 3.1 | SMB 3.1.1 session |
| `OpenAccmode` 131209 | `0x20089` | READ_CONTROL + READ_ATTRIBUTES + READ_EA + READ_DATA (generic read) |
| `OpenAccmode` 393631 | `0x6019F` | WRITE_DAC + READ_CONTROL + DELETE + read/write data, attributes, EA (Explorer reopening a new file) |
| `OpenAccmode` 65664 | `0x10080` | DELETE + READ_ATTRIBUTES (Explorer rename) |
| `OpenSharemode` | 0, 1, 3, 7 | none, read, read + write, read + write + delete |
| `OpenOptions` 96 / 100 | `0x60` / `0x64` | NON_DIRECTORY_FILE + SYNCHRONOUS_IO_NONALERT (+ SEQUENTIAL_ONLY) |
| `OpenOptions` 4194404 | `0x400064` | as above + OPEN_NO_RECALL (PowerShell / .NET) |
| `OpenOptions` 2097184 | `0x200020` | OPEN_REPARSE_POINT + SYNCHRONOUS_IO_NONALERT |
| `SmbCloseReq` | `RdBytes`, `WrBytes` | Bytes read and written on that handle |

**SCREEN_RESP sent by `fpolicy_av.py`**

```xml
<?xml version="1.0"?><Header><NotfType>SCREEN_RESP</NotfType><ContentLen>…</ContentLen><DataFormat>XML</DataFormat></Header>

<?xml version="1.0"?><FscreenResp><ReqId>3075</ReqId><ReqType>SMB_OPEN</ReqType><NotfResp>2</NotfResp></FscreenResp>
```

**clamd INSTREAM (TCP 127.0.0.1:3310, one connection per scan)**

| Direction | Bytes |
|-----------|-------|
| → | `zINSTREAM\0` |
| → | For each chunk of up to 64 KiB: 4-byte big-endian length + data |
| → | `00 00 00 00` (end of stream) |
| ← | `stream: OK\0` or `stream: Lab.EICAR-Test-File.UNOFFICIAL FOUND\0` |

The signature in `lab_eicar.ndb` is `Lab.EICAR-Test-File:0:*:<hex of the 68-byte string>`: target any file type, at any offset.

**Timers in effect**

| Component | Setting | Value |
|-----------|---------|-------|
| FPolicy engine `av_engine` | Cancel request / abort request | 20 s / 40 s |
| | Status request interval | 10 s |
| | Keep-alive interval | 2 min |
| | Disconnect non-responsive server | 1 min |
| | Max outstanding requests / reconnect attempts | 500 / 5 |
| | Receive / send buffer | 256 KiB / 1 MiB |
| FPolicy policy `av_pol` | Mandatory | false (fail-open) |
| Vscan `fake_pool` (cluster1) | Request service / scan queue / session setup timeout | 30 s / 20 s / 10 s |
| Write-back (documented) | Dirty data record size / flush start | ~20 MB / after ~40 MB |
| | Cache mtime scrubber | every 5 min, files idle 2 min |
| | Origin mtime scrubber | every 5 min, recalls delegations idle 15 min |
| Windows SMB client | Directory / file info / file-not-found cache | 10 s / 10 s / 5 s |

**Observed timings (decision log)**

| Event | End-to-end time |
|-------|-----------------|
| Origin open denied by Vscan (no scanner) | ~16 ms |
| FPolicy open, first scan | 2.4–4.5 s |
| FPolicy open, cached verdict | 0.8–1.6 s |
| FPolicy deny from the verdict cache | 1.2 s |

**Where to capture**

| Capture point | Command or tool | What you get |
|---------------|-----------------|--------------|
| Jumphost NIC | Wireshark (if installed), or `netsh trace start capture=yes` then convert the `.etl` | SMB2 to both SVMs (clear text), FPolicy XML on 9898 (clear text) |
| Jumphost loopback | Npcap loopback adapter | clamd `INSTREAM` on 3310 |
| cluster2 port `e0e` (data LIF and `ic_lif1`) | `network tcpdump start -node cluster2-01 -port e0e` / `network tcpdump stop ...` (check the options with `?`) | Client SMB, FPolicy, RAL (TLS) on the cache side |
| cluster1 ports `e0h` (data) / `e0d` (`ic_lif1`) | `network tcpdump start -node cluster1-01 -port e0d` | RAL (TLS) at the origin, origin SMB |

---

## 11. From lab to pilot

What the lab shows can be achieved, and what a pilot would add:

| Area | Lab (this document) | Pilot (Linux pilot runbook) |
|------|---------------------|-------------------------------|
| Where scanning happens | At the FlexCache, on open and after close | Same, alongside the supported on-demand scans at the origin |
| Scanner hosts | 1 Windows host across the WAN | 2-3 Linux hosts (for example EC2) on the cache's LAN or VPC, load-shared by ONTAP |
| File access | `c$` as a domain administrator | Read-only `scan$` share, dedicated service account |
| Large files | Over 25 MB not scanned | Up to 100 MB scanned while the open waits; larger files scanned in the background |
| Verdicts | In memory, one scanner | Shared Redis/Valkey cache, optional automatic failover |
| Failure handling | Fail-open | Fail-open or fail-closed, always answered before ONTAP's timeout |
| AV engine | ClamAV with a test signature | ClamAV with the official signatures (a commercial engine with a scanning interface could replace it; to be confirmed with the vendor) |
| FPolicy channel | Plain text, no authentication | Restricted to the SVM data LIFs (security groups / allow list); FPolicy TLS optional |

Suggested pilot success criteria:

1. EICAR written through each cache type is blocked at the next open (FP-1 to FP-3).
2. Clean-file open latency stays within an agreed budget.
3. No unscanned opens during scanner restarts with fail-closed (FP-8).
4. Measured open and scan rates are recorded, for sizing.
