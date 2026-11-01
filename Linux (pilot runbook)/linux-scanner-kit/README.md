# FlexCache AV scanner kit - Linux

Everything needed to build the Linux FPolicy antivirus scanner described in
`FlexCache_AV_Linux_Pilot_Runbook.html` (next to this folder): ONTAP / FSx for NetApp ONTAP
FPolicy (synchronous) → `fpolicy_av_linux.py` → ClamAV, with an optional shared Redis/Valkey
verdict cache. Target: **Ubuntu 22.04 or 24.04**, for example on Amazon EC2.

This is a prototype for a pilot, provided as is. It is not a NetApp-supported antivirus
integration.

## Contents

| File | Purpose |
|------|---------|
| `setup_scanner.py` | Scanner wizard: ClamAV, read-only `scan$` mounts, configuration, the `fpolicy-av` service, self-tests, and the ONTAP commands to run |
| `setup_cache.py` | Cache wizard: Redis or Valkey as primary, replica or Sentinel-only (optional) |
| `fpolicy_av_linux.py` | The FPolicy server. `setup_scanner.py` installs it in `/opt/fpolicy-av/` |
| `tests/test_server.py` | Optional end-to-end test of the server on a scanner host |
| `NOTICE.txt` | Where ClamAV and the other packages come from, and their licences |

ClamAV, cifs-utils and Redis/Valkey are not in the kit. The wizards install them from
Ubuntu's own repositories, so they keep receiving Ubuntu security updates. The hosts therefore
need access to an Ubuntu mirror (directly, through NAT or through a proxy). They need that
anyway to download the ClamAV signatures.

## Quick start

1. **Hosts:** Ubuntu 22.04 or 24.04 with 4 GB of RAM or more (the full ClamAV database needs
   about 1.5 GB), on a network that reaches the SVM.
2. **Network / security groups:**
   - scanners: inbound TCP 9898 from the SVM data LIF IPs;
   - SVM: inbound TCP 445 from the scanners;
   - cache nodes (only with a shared cache): inbound TCP 6379 and 26379 from the scanners and
     the other cache nodes.
3. **ONTAP, first:** create the `scan$` share. The scanner wizard prints the four commands in
   its summary; they are also in section 6.3 of the runbook.
4. **Copy this folder** to each host, for example `scp -r linux-scanner-kit ubuntu@<ip>:~/`.
5. **Cache nodes (optional), primary first:** `sudo python3 setup_cache.py`.
6. **Scanner:** `cd linux-scanner-kit && sudo python3 setup_scanner.py`.
   Run it with `--dry-run` first to see every step and file without changing anything.
7. **ONTAP:** run the FPolicy commands the wizard prints (they are also saved in
   `/etc/fpolicy-av/ontap-commands.txt`), then check `vserver fpolicy show-engine`.
8. **Watch:** `sudo tail -f /var/log/fpolicy-av/fpolicy_av.log`.

Every wizard step prints:
- the command it runs, its output, its exit code and how long it took;
- every file it writes, with secrets masked.

A full transcript goes to `/var/log/fpolicy-av-setup/`.

## Useful commands

| Command | What it does |
|---------|--------------|
| `sudo python3 setup_scanner.py --dry-run` | Ask the questions and show every step, change nothing |
| `sudo python3 setup_scanner.py --answers /etc/fpolicy-av/wizard-answers.json` | Re-run with the previous answers as defaults |
| `sudo python3 setup_scanner.py --answers wizard-answers.json --non-interactive` | Unattended install on the next scanners (secrets from environment variables, see `--help`) |
| `sudo python3 setup_scanner.py --uninstall` | Remove what the wizard installed (packages are kept) |
| `sudo -u fpolicy-av python3 /opt/fpolicy-av/fpolicy_av_linux.py --check` | Health check: clamd, fdpass scan of a real file, mounts, cache |
| `sudo -u fpolicy-av python3 /opt/fpolicy-av/fpolicy_av_linux.py --selftest` | Play ONTAP against the running service |

`setup_cache.py` has the same `--dry-run`, `--answers`, `--non-interactive` and `--uninstall`
options.

## Requirements

- Python 3.8 or later. Ubuntu 22.04 ships 3.10 and 24.04 ships 3.12; nothing else is needed
  from PyPI.
- Root (sudo) and systemd.
