#!/usr/bin/env python3
"""Scanner wizard for the Linux FPolicy AV scanner (version 2).

Turns an Ubuntu 22.04 / 24.04 host (an EC2 instance, for example) into an
FPolicy antivirus scanner for ONTAP / FSx for NetApp ONTAP:

  ClamAV (clamd)  +  read-only CIFS mounts of each SVM's scan$ share
                  +  fpolicy_av_linux.py as the systemd service fpolicy-av

It runs in four phases and prints everything it does:
  1. preflight checks (OS, EC2 metadata, memory, network)    - changes nothing
  2. questions                                               - changes nothing
  3. summary and confirmation                                - changes nothing
  4. numbered install steps: every command, its output, exit code and time,
     every file written (secrets masked), and a self-test at the end

Usage (from the folder that holds fpolicy_av_linux.py):
  sudo python3 setup_scanner.py                  interactive install
  sudo python3 setup_scanner.py --dry-run        show every step, change nothing
  sudo python3 setup_scanner.py --answers FILE   reuse answers (e.g. from scanner-1)
  sudo python3 setup_scanner.py --answers FILE --non-interactive
                                                 unattended (passwords from env)
  sudo python3 setup_scanner.py --uninstall      remove what this wizard installed

Environment for --non-interactive:
  FPAV_SVM_PASSWORD_<VSERVER>  (or FPAV_SVM_PASSWORD for all SVMs)
  FPAV_CACHE_PASSWORD          (only if the shared cache needs a password)

The ONTAP commands are printed and saved, never applied.
Lab tool. Not a NetApp-supported antivirus integration.
"""

import argparse
import datetime
import difflib
import getpass
import glob
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.request

WIZARD = "setup_scanner"
WIZARD_VERSION = "2.0"
HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_SRC = os.path.join(HERE, "fpolicy_av_linux.py")

CONF_DIR = "/etc/fpolicy-av"
CONF = os.path.join(CONF_DIR, "scanner.conf")
CRED_DIR = os.path.join(CONF_DIR, "creds")
ANSWERS = os.path.join(CONF_DIR, "wizard-answers.json")
ONTAP_TXT = os.path.join(CONF_DIR, "ontap-commands.txt")
LOG_DIR = "/var/log/fpolicy-av"
SETUP_LOG_DIR = "/var/log/fpolicy-av-setup"
OPT_DIR = "/opt/fpolicy-av"
SERVER_DST = os.path.join(OPT_DIR, "fpolicy_av_linux.py")
SERVICE = "fpolicy-av.service"
SERVICE_FILE = "/etc/systemd/system/" + SERVICE
LOGROTATE = "/etc/logrotate.d/fpolicy-av"
SVC_USER = "fpolicy-av"
SVC_HOME = "/var/lib/fpolicy-av"
DEFAULT_MNT_ROOT = "/mnt/fpolicy-av"

CLAMD_CONF = "/etc/clamav/clamd.conf"
FRESHCLAM_CONF = "/etc/clamav/freshclam.conf"
CLAMD_SOCK = "/run/clamav/clamd.ctl"
CLAMD_DB = "/var/lib/clamav"
LAB_SIG = os.path.join(CLAMD_DB, "lab_eicar.ndb")
CLAMD_DROPINS = ["/etc/systemd/system/clamav-daemon.service.d/fpolicy-av.conf",
                 "/etc/systemd/system/clamav-daemon.socket.d/fpolicy-av.conf"]
APPARMOR_PROFILE = "/etc/apparmor.d/usr.sbin.clamd"
APPARMOR_LOCAL = "/etc/apparmor.d/local/usr.sbin.clamd"
APT_PROXY_CONF = "/etc/apt/apt.conf.d/95fpolicy-av-proxy"

PACKAGES = ["clamav", "clamav-daemon", "clamav-freshclam", "clamdscan", "cifs-utils", "keyutils",
            "python3-redis", "ca-certificates"]
SYNC_LIMIT_MAX_MB = 100
CLAMAV_CDN = "database.clamav.net"
EICAR_HEX = ("58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
             "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a")


# ======================= BEGIN COMMON (same in setup_scanner.py / setup_cache.py)
class StepError(Exception):
    """A step failed: the wizard offers retry, skip or abort."""


class Result:
    def __init__(self, rc, out, timed_out=False):
        self.rc, self.out, self.timed_out = rc, out, timed_out

    @property
    def ok(self):
        return self.rc == 0


class UI:
    """Console + log output, prompts and command runner.

    Everything printed also goes to the install log, with secrets masked.
    """
    BOLD, DIM, RED, GREEN, YELLOW, CYAN = "1", "2", "31", "32", "33", "36"
    RULE = "=" * 78
    LINE = "-" * 78

    def __init__(self, dry_run=False, interactive=True):
        self.dry_run = dry_run
        self.interactive = interactive
        self.color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.secrets = []
        self.log_fh = None
        self.log_path = None
        self.pending = []
        self.backed_up = set()
        self.run_stamp = time.strftime("%Y%m%d-%H%M%S")
        self.step_status = "ok"

    # ---- output ----
    def add_secret(self, value):
        if value and len(value) >= 3 and value not in self.secrets:
            self.secrets.append(value)

    def mask(self, text):
        for s in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(s, "********")
        return text

    def _paint(self, code, text):
        return f"\033[{code}m{text}\033[0m" if (self.color and code) else text

    def _log(self, text):
        line = f"{time.strftime('%H:%M:%S')} {text}\n"
        if self.log_fh:
            self.log_fh.write(line)
            self.log_fh.flush()
        else:
            self.pending.append(line)

    def emit(self, text="", code=None):
        text = self.mask(str(text))
        print(self._paint(code, text), flush=True)
        self._log(text)

    def open_log(self, directory, name):
        if self.dry_run:
            directory = tempfile.gettempdir()
            name = name + "-dryrun"
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.log_path = os.path.join(directory, f"{name}-{self.run_stamp}.log")
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.log_fh = os.fdopen(fd, "a", encoding="utf-8")
        for line in self.pending:
            self.log_fh.write(line)
        self.pending = []
        self.log_fh.flush()

    def banner(self, title, subtitle=""):
        self.emit(self.RULE, self.BOLD)
        self.emit(f" {title}", self.BOLD)
        if subtitle:
            for ln in subtitle.splitlines():
                self.emit(f" {ln}")
        self.emit(self.RULE, self.BOLD)

    def phase(self, n, total, title):
        self.emit("")
        self.emit(self.RULE, self.BOLD)
        self.emit(f" PHASE {n} of {total}: {title}", self.BOLD)
        self.emit(self.RULE, self.BOLD)

    def section(self, title):
        self.emit("")
        self.emit(f"--- {title} " + "-" * max(3, 74 - len(title)), self.BOLD)

    def step_header(self, i, n, title, why):
        self.step_status = "ok"
        self.emit("")
        self.emit(self.LINE, self.CYAN)
        self.emit(f"[{i:>2}/{n}] {title}", self.BOLD)
        for ln in textwrap.wrap(why, 70):
            self.emit(f"        {ln}", self.DIM)
        self.emit(self.LINE, self.CYAN)

    def say(self, msg):
        self.emit(f"  {msg}")

    def note(self, msg):
        for i, ln in enumerate(textwrap.wrap(msg, 74) or [""]):
            self.emit(f"  {'-' if i == 0 else ' '} {ln}", self.DIM)

    def kv(self, key, value):
        self.emit(f"    {key:<28} {value}")

    def ok(self, msg):
        self.emit(f"  [ OK ] {msg}" + ("  (dry run)" if self.dry_run else ""), self.GREEN)

    def warn(self, msg):
        if self.step_status == "ok":
            self.step_status = "warn"
        self.emit(f"  [WARN] {msg}", self.YELLOW)

    def fail(self, msg):
        self.step_status = "fail"
        self.emit(f"  [FAIL] {msg}", self.RED)

    def skip(self, msg):
        """Something was skipped; a step function returns "skip" when all of it was."""
        self.emit(f"  [SKIP] {msg}", self.DIM)

    def block(self, text, prefix="    | ", limit=200):
        lines = text.splitlines()
        for ln in lines[:limit]:
            self.emit(prefix + ln, self.DIM)
        if len(lines) > limit:
            self.emit(f"{prefix}... ({len(lines) - limit} more lines)", self.DIM)

    # ---- prompts ----
    def _input(self, prompt, secret=False):
        try:
            return getpass.getpass(prompt) if secret else input(prompt)
        except EOFError:
            raise SystemExit("\ninput closed: aborted")

    def ask(self, prompt, default=None, validate=None, help=None, allow_empty=False):
        if help and self.interactive:
            for ln in textwrap.wrap(help, 72):
                self.emit(f"      {ln}", self.DIM)
        while True:
            if self.interactive:
                suffix = f" [{default}]" if default not in (None, "") else ""
                val = self._input(f"  ? {prompt}{suffix}: ").strip()
                if val == "" and default is not None:
                    val = str(default)
            else:
                val = "" if default is None else str(default)
            if val == "" and not allow_empty:
                if not self.interactive:
                    raise SystemExit(f"--non-interactive: no value for: {prompt}")
                self.emit("      a value is required", self.YELLOW)
                continue
            if validate and val != "":
                good, res = validate(val)
                if not good:
                    if not self.interactive:
                        raise SystemExit(f"--non-interactive: {prompt}: {res}")
                    self.emit(f"      {res}", self.YELLOW)
                    continue
                val = res
            self._log(f"  ? {prompt}: {val}")
            if not self.interactive:
                self.emit(f"  ? {prompt}: {val}  (from answers)")
            return val

    def ask_yes(self, prompt, default=True, help=None):
        d = "Y/n" if default else "y/N"
        if help and self.interactive:
            for ln in textwrap.wrap(help, 72):
                self.emit(f"      {ln}", self.DIM)
        while True:
            if not self.interactive:
                self.emit(f"  ? {prompt}: {'yes' if default else 'no'}  (from answers)")
                return default
            val = self._input(f"  ? {prompt} ({d}): ").strip().lower()
            if val == "":
                ans = default
            elif val in ("y", "yes"):
                ans = True
            elif val in ("n", "no"):
                ans = False
            else:
                self.emit("      answer y or n", self.YELLOW)
                continue
            self._log(f"  ? {prompt}: {'yes' if ans else 'no'}")
            return ans

    def ask_int(self, prompt, default, lo, hi, help=None):
        def v(x):
            try:
                n = int(x)
            except ValueError:
                return False, "enter a whole number"
            return (True, n) if lo <= n <= hi else (False, f"must be between {lo} and {hi}")
        return self.ask(prompt, default, v, help)

    def ask_choice(self, prompt, choices, default, help=None):
        def v(x):
            x = x.lower()
            return (True, x) if x in choices else (False, f"choose one of: {', '.join(choices)}")
        return self.ask(f"{prompt} ({'/'.join(choices)})", default, v, help)

    def ask_secret(self, prompt, env_names=(), confirm=True, allow_empty=False):
        if not self.interactive:
            for name in env_names:
                if os.environ.get(name) and len(os.environ[name]) < 4:
                    raise SystemExit(f"${name}: use at least 4 characters")
                if os.environ.get(name):
                    self.emit(f"  ? {prompt}: ******** (from ${name})")
                    self.add_secret(os.environ[name])
                    return os.environ[name]
            if allow_empty:
                return ""
            raise SystemExit(f"--non-interactive: set {' or '.join(env_names)}")
        while True:
            pw = self._input(f"  ? {prompt}: ", secret=True)
            if not pw and not allow_empty:
                self.emit("      a value is required", self.YELLOW)
                continue
            if pw and len(pw) < 4:
                self.emit("      use at least 4 characters", self.YELLOW)
                continue
            if pw and confirm and self._input("  ? again, to confirm: ", secret=True) != pw:
                self.emit("      the two entries differ, try again", self.YELLOW)
                continue
            self.add_secret(pw)
            self._log(f"  ? {prompt}: ********")
            return pw

    # ---- commands ----
    def run(self, cmd, check=True, timeout=None, env=None, changes=True, show=True,
            input_text=None, quiet_cmd=False):
        """Run a command, print it, stream its output, print exit code and time.

        changes=False marks read-only commands: they also run in --dry-run.
        """
        disp = cmd if isinstance(cmd, str) else " ".join(shlex.quote(str(c)) for c in cmd)
        if not quiet_cmd:
            self.emit(f"  $ {disp}", self.CYAN)
        if self.dry_run and changes:
            self.emit("    (dry run: not executed)", self.DIM)
            return Result(0, "")
        full_env = dict(os.environ)
        full_env.update(env or {})
        t0 = time.time()
        try:
            p = subprocess.Popen(cmd, shell=isinstance(cmd, str), stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=full_env,
                                 stdin=subprocess.PIPE if input_text else subprocess.DEVNULL)
        except OSError as e:
            self.emit(f"    -> cannot run: {e}", self.RED)
            if check:
                raise StepError(f"cannot run {disp}: {e}")
            return Result(127, str(e))
        timed_out = []
        timer = None
        if timeout:
            def kill():
                timed_out.append(True)
                p.kill()
            timer = threading.Timer(timeout, kill)
            timer.start()
        if input_text:
            p.stdin.write(input_text.encode())
            p.stdin.close()
        lines = []
        for raw in p.stdout:
            # keep only the last state of \r progress updates
            line = raw.decode("utf-8", "replace").rstrip("\n").split("\r")[-1].rstrip()
            lines.append(line)
            if show:
                self.emit(f"    | {line}", self.DIM)
        rc = p.wait()
        if timer:
            timer.cancel()
        dt = time.time() - t0
        if timed_out:
            self.emit(f"    -> killed after {timeout:.0f} s timeout", self.RED)
            rc = 124
        else:
            self.emit(f"    -> exit {rc} ({dt:.1f} s)", self.GREEN if rc == 0 else self.YELLOW)
        if check and rc != 0:
            raise StepError(f"command failed (exit {rc}): {self.mask(disp)}")
        return Result(rc, "\n".join(lines), bool(timed_out))

    def probe(self, cmd, timeout=15):
        """Quiet read-only command: returns (rc, output) without printing."""
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                               text=True, timeout=timeout)
            return p.returncode, (p.stdout + p.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            return 127, str(e)

    # ---- files ----
    def write_file(self, path, content, mode=0o644, owner=None, show="content",
                   backup=True):
        """Write a file (atomically), printing what changes. show: content|diff|none."""
        old = None
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    old = f.read()
            except OSError:
                old = None
        own = f", owner {owner[0]}:{owner[1]}" if owner else ""
        if old == content:
            self.say(f"unchanged: {path} (mode {mode:04o}{own})")
        else:
            verb = "update" if old is not None else "create"
            self.say(f"{verb}: {path} (mode {mode:04o}{own}, {len(content.splitlines())} lines)")
            if show == "diff" and old is not None:
                diff = list(difflib.unified_diff(old.splitlines(), content.splitlines(),
                                                 "before", "after", n=1, lineterm=""))
                self.block("\n".join(diff[2:]) or "(whitespace only)", limit=120)
            elif show != "none":
                self.block(content, limit=120)
        if self.dry_run:
            self.emit("    (dry run: not written)", self.DIM)
            return
        if old is not None and old != content and backup and path not in self.backed_up:
            bak = f"{path}.fpav-backup-{self.run_stamp}"
            shutil.copy2(path, bak)
            self.backed_up.add(path)
            self.note(f"previous version saved as {bak}")
        d = os.path.dirname(path)
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".fpav-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, mode)
        if owner:
            shutil.chown(tmp, owner[0], owner[1])
        elif old is not None:
            st = os.stat(path)   # keep the current owner (e.g. redis:redis)
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
        if old == content:
            os.chmod(path, mode)
            if owner:
                shutil.chown(path, owner[0], owner[1])

    def remove_path(self, path):
        if not os.path.lexists(path):
            self.say(f"not present: {path}")
            return
        self.say(f"remove: {path}")
        if self.dry_run:
            self.emit("    (dry run: not removed)", self.DIM)
            return
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)

    def mkdir(self, path, mode=0o755, owner=None, enforce=True):
        """Create a directory; enforce=False leaves an existing one's mode/owner alone."""
        exists = os.path.isdir(path)
        if exists and os.path.ismount(path):
            self.say(f"directory exists: {path} (a mount point: left as it is)")
            return
        if exists and not enforce:
            self.say(f"directory exists: {path} (left as it is)")
            return
        own = f", owner {owner[0]}:{owner[1]}" if owner else ""
        self.say(f"{'directory exists' if exists else 'create directory'}: {path} "
                 f"(mode {mode:04o}{own})")
        if self.dry_run:
            return
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)
        if owner:
            shutil.chown(path, owner[0], owner[1])


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def tcp_check(host, port, timeout=3.0):
    t0 = time.time()
    try:
        socket.create_connection((host, int(port)), timeout=timeout).close()
        return True, (time.time() - t0) * 1000, ""
    except OSError as e:
        return False, (time.time() - t0) * 1000, str(e) or e.__class__.__name__


def resolve_host(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def os_release():
    info = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v.strip().strip('"')
    return info


def meminfo_mb():
    m = re.search(r"MemTotal:\s+(\d+)", read_text("/proc/meminfo"))
    return int(m.group(1)) // 1024 if m else 0


def disk_free_mb(path):
    while path and not os.path.exists(path):
        path = os.path.dirname(path)
    st = os.statvfs(path or "/")
    return st.f_bavail * st.f_frsize // (1024 * 1024)


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))   # no packet is sent
            return s.getsockname()[0]
    except OSError:
        return ""


def ec2_metadata():
    """IMDSv2 lookup (1 s timeouts, no proxy). None when not on EC2."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = "http://169.254.169.254/latest/"
    try:
        req = urllib.request.Request(base + "api/token", method="PUT",
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
        token = opener.open(req, timeout=1).read().decode()
    except Exception:
        return None

    def get(path):
        try:
            r = urllib.request.Request(base + "meta-data/" + path,
                                       headers={"X-aws-ec2-metadata-token": token})
            return opener.open(r, timeout=1).read().decode().strip()
        except Exception:
            return ""
    md = {k: get(p) for k, p in (("instance_id", "instance-id"),
                                 ("instance_type", "instance-type"),
                                 ("az", "placement/availability-zone"),
                                 ("region", "placement/region"),
                                 ("private_ip", "local-ipv4"),
                                 ("mac", "mac"))}
    if md.get("mac"):
        md["vpc_id"] = get(f"network/interfaces/macs/{md['mac']}/vpc-id")
        md["subnet_id"] = get(f"network/interfaces/macs/{md['mac']}/subnet-id")
        md["sg_ids"] = get(f"network/interfaces/macs/{md['mac']}/security-group-ids").replace("\n", ",")
    return md


def apt_mirror_hosts():
    hosts = []
    files = ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.list") \
        + glob.glob("/etc/apt/sources.list.d/*.sources")
    for f in files:
        for m in re.finditer(r"(?m)^(?:deb\s+(?:\[[^\]]*\]\s+)?|URIs:\s*)(https?)://([^/\s:]+)",
                             read_text(f)):
            item = (m.group(1), m.group(2))
            if item not in hosts:
                hosts.append(item)
    return hosts


def systemd_running():
    return os.path.isdir("/run/systemd/system")


def managed_block(text, name, lines, comment="#"):
    """Replace or append the block between our markers."""
    begin = f"{comment} >>> {name} (managed by fpolicy-av wizard) >>>"
    end = f"{comment} <<< {name} <<<"
    body = "\n".join([begin] + list(lines) + [end])
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    if pattern.search(text):
        return pattern.sub(lambda _: body, text, count=1)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + ("\n" if text else "") + body + "\n"


def remove_managed_block(text, name, comment="#"):
    begin = f"{comment} >>> {name} (managed by fpolicy-av wizard) >>>"
    end = f"{comment} <<< {name} <<<"
    pattern = re.compile(r"\n?" + re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)
    return pattern.sub("\n", text).rstrip("\n") + "\n" if pattern.search(text) else text


def v_host(x):
    x = x.strip()
    try:
        ipaddress.ip_address(x)
        return True, x
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", x):
        return True, x
    return False, "enter an IP address or a DNS name"


def v_port(x):
    return (True, int(x)) if x.isdigit() and 1 <= int(x) <= 65535 else (False, "enter a port 1-65535")


def v_abs_path(x):
    x = x.strip().rstrip("/") or "/"
    if not x.startswith("/") or " " in x:
        return False, "enter an absolute path without spaces"
    return True, os.path.normpath(x)


def v_ip_list(x):
    out = []
    for item in re.split(r"[,\s]+", x.strip()):
        if not item:
            continue
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            return False, f"'{item}' is not an IP address or CIDR"
    return True, ",".join(out)


def v_host_list(x):
    out = []
    for item in re.split(r"[,\s]+", x.strip()):
        if not item:
            continue
        host, _, port = item.rpartition(":")
        if not host or not port.isdigit():
            return False, f"'{item}': use host:port"
        out.append(item)
    return (True, ",".join(out)) if out else (False, "enter at least one host:port")
# ======================= END COMMON


# ------------------------------------------------------------- validators ---
def v_share(x):
    x = x.strip()
    if not x or re.search(r'[\\/:*?"<>|\s]', x) or len(x) > 80:
        return False, "share names can't contain spaces or \\ / : * ? \" < > |"
    return True, x


def v_ns_path(x):
    x = "/" + x.strip().strip("/")
    if "\\" in x or " " in x:
        return False, "use a namespace path like /vol1 or /vol1/dept (no spaces)"
    return True, os.path.normpath(x)


def v_account(x):
    x = x.strip()
    if not x or " " in x:
        return False, "enter DOMAIN\\user, user@domain or user"
    return True, x


def v_proxy(x):
    if re.fullmatch(r"https?://[^\s/:]+:\d+/?", x.strip()):
        return True, x.strip().rstrip("/")
    return False, "use http://host:port"


def split_user(account):
    if "\\" in account:
        dom, name = account.split("\\", 1)
        return name, dom
    if "@" in account:
        name, dom = account.split("@", 1)
        return name, dom
    return account, ""


def env_key(vserver):
    return "FPAV_SVM_PASSWORD_" + re.sub(r"[^A-Za-z0-9]", "_", vserver).upper()


def load_server_module():
    if not os.path.exists(SERVER_SRC):
        raise SystemExit(f"{SERVER_SRC} not found: run the wizard from the Linux Fpol folder")
    sys.path.insert(0, HERE)
    import fpolicy_av_linux
    return fpolicy_av_linux


# ============================================================== PHASE 1 =====
def preflight(ui, args):
    ui.phase(1, 4, "Preflight checks (read-only)")
    facts = {"fail": False}

    def row(status, label, detail):
        fn = {"OK": ui.ok, "WARN": ui.warn, "FAIL": ui.fail, "INFO": ui.say}[status]
        fn(f"{label:<26} {detail}" if status != "INFO" else f"[INFO] {label:<26} {detail}")
        if status == "FAIL":
            facts["fail"] = True

    is_root = os.geteuid() == 0
    row("OK" if is_root else ("WARN" if args.dry_run else "FAIL"), "running as root",
        "yes" if is_root else "no (run with sudo)")

    osr = os_release()
    facts["os"] = osr
    name = f"{osr.get('PRETTY_NAME', 'unknown')}"
    if osr.get("ID") == "ubuntu" and osr.get("VERSION_ID") in ("22.04", "24.04"):
        row("OK", "operating system", name)
    elif shutil.which("apt-get"):
        row("WARN", "operating system", f"{name} (tested on Ubuntu 22.04 and 24.04 only)")
    else:
        row("FAIL", "operating system", f"{name}: needs Ubuntu (apt)")

    row("OK" if sys.version_info >= (3, 8) else "FAIL", "python",
        sys.version.split()[0] + ("" if sys.version_info >= (3, 8) else " (needs 3.8+)"))
    row("OK" if systemd_running() else ("WARN" if args.dry_run else "FAIL"), "systemd",
        "running" if systemd_running() else "not PID 1 (the service needs systemd)")
    row("OK" if os.path.exists(SERVER_SRC) else "FAIL", "fpolicy_av_linux.py",
        SERVER_SRC if os.path.exists(SERVER_SRC) else "missing next to this wizard")

    md = ec2_metadata()
    facts["ec2"] = md
    if md:
        row("OK", "EC2 instance", f"{md.get('instance_id')} ({md.get('instance_type')}, "
                                  f"{md.get('az')})")
        ui.kv("private IP", md.get("private_ip", ""))
        ui.kv("VPC / subnet", f"{md.get('vpc_id', '')} / {md.get('subnet_id', '')}")
        ui.kv("security groups", md.get("sg_ids", ""))
    else:
        row("INFO", "EC2 instance", "no instance metadata (not EC2, or IMDS disabled)")
    facts["ip"] = (md or {}).get("private_ip") or primary_ip()
    row("INFO", "primary IP address", facts["ip"] or "unknown")

    cpus = os.cpu_count() or 1
    mem = meminfo_mb()
    facts["cpus"], facts["mem_mb"] = cpus, mem
    mem_status = "OK" if mem >= 3800 else "WARN"
    row(mem_status, "CPU / memory", f"{cpus} vCPU, {mem} MB RAM" +
        ("" if mem >= 3800 else " (the full ClamAV database needs ~1.5 GB, more "
                                "while reloading: 4 GB+ recommended)"))
    free = disk_free_mb(CLAMD_DB)
    row("OK" if free >= 2048 else "WARN", "free disk for signatures", f"{free} MB")

    rc, out = ui.probe(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    row("OK" if out.strip() == "yes" else "WARN", "clock synchronised",
        out.strip() or "unknown (SMB/AD logins need a correct clock)")

    mirrors = apt_mirror_hosts()
    facts["mirror_ok"] = True
    for scheme, host in mirrors[:3]:
        ok, ms, err = tcp_check(host, 443 if scheme == "https" else 80, 5)
        row("OK" if ok else "WARN", "package mirror", f"{host} {'reachable' if ok else err} "
                                                     f"({ms:.0f} ms)")
        facts["mirror_ok"] = facts["mirror_ok"] and ok
    if not mirrors:
        row("WARN", "package mirror", "no apt sources found")
    ok, ms, err = tcp_check(CLAMAV_CDN, 443, 5)
    facts["cdn_ok"] = ok
    row("OK" if ok else "WARN", "ClamAV signature CDN",
        f"{CLAMAV_CDN} {'reachable' if ok else err} ({ms:.0f} ms)")

    rc, _ = ui.probe(["modinfo", "cifs"])
    facts["cifs_module"] = rc == 0
    row("OK" if rc == 0 else "WARN", "kernel SMB client (cifs)",
        "available" if rc == 0 else "missing: the wizard will install linux-modules-extra")

    rc, out = ui.probe(["ufw", "status"])
    facts["ufw_active"] = "Status: active" in out
    row("INFO", "host firewall (ufw)", "active" if facts["ufw_active"] else
        "inactive or not installed (normal on EC2: security groups filter traffic)")

    existing = [p for p in (CONF, SERVICE_FILE, SERVER_DST) if os.path.exists(p)]
    facts["existing"] = bool(existing)
    if existing:
        row("INFO", "existing installation", ", ".join(existing) +
            " (re-run: previous answers are offered as defaults)")
    else:
        row("INFO", "existing installation", "none")

    if facts["fail"] and not args.dry_run:
        ui.emit("")
        ui.fail("preflight found blocking problems (FAIL above). Fix them and re-run.")
        sys.exit(2)
    return facts


# ============================================================== PHASE 2 =====
def ask_svm(ui, prev):
    prev = prev or {}
    ui.section("SVM")
    vserver = ui.ask("SVM (vserver) name", prev.get("vserver"),
                     help="The SVM that owns the cache shares. FSx for ONTAP: the SVM name "
                          "in the FSx console (e.g. svm1).")
    cifs = ui.ask("CIFS server name, as in \\\\NAME\\share",
                  prev.get("cifs_server") or vserver.upper(),
                  help="ONTAP puts this name in every FPolicy request (DisplayPath). "
                       "ONTAP: vserver cifs show -vserver <svm> -fields cifs-server. "
                       "FSx: the SVM's SMB server (NetBIOS) name.")
    host = ui.ask("SMB endpoint: data LIF IP or DNS name", prev.get("host"), v_host,
                  help="Where this host mounts scan$. FSx: the SVM's SMB endpoint DNS name or "
                       "IP address (Endpoints tab).")
    scan_share = ui.ask("scan$ share name", prev.get("scan_share", "scan$"), v_share,
                        help="A hidden share only the scanner uses (created with the ONTAP "
                             "commands shown in the summary). It is outside the FPolicy scope, "
                             "so the scanner's own reads are not screened.")
    scan_root = ui.ask("scan$ share path in the SVM namespace", prev.get("scan_root", "/"),
                       v_ns_path, help="'/' (the namespace root) reaches every volume.")
    mnt = ui.ask("local mount point", prev.get("mnt", f"{DEFAULT_MNT_ROOT}/{vserver}"),
                 v_abs_path)
    vers = ui.ask_choice("SMB dialect", ["3.1.1", "3.0", "2.1"], prev.get("smb_version", "3.1.1"))
    acct_default = (f"{prev['domain']}\\{prev['user']}" if prev.get("user") and prev.get("domain")
                    else prev.get("user"))
    account = ui.ask("domain account that mounts scan$", acct_default, v_account,
                     help="DOMAIN\\user or user@domain. Read-only on scan$ and NTFS read on the "
                          "files is enough; a dedicated service account is best (e.g. "
                          "CORP\\svc_fpav).")
    user, dom = split_user(account)
    if not dom:
        dom = ui.ask("  domain (NetBIOS name, e.g. CORP)", prev.get("domain"))
    password = ui.ask_secret(f"password for {dom}\\{user}", (env_key(vserver), "FPAV_SVM_PASSWORD"))
    ui.say("User-facing shares under this SVM (the shares FPolicy watches):")
    shares = {}
    prev_shares = list((prev.get("shares") or {}).items())
    i = 0
    while True:
        d_name, d_path = prev_shares[i] if i < len(prev_shares) else (None, None)
        name = ui.ask("  share name (blank when done)", d_name, v_share, allow_empty=True,
                      help=("ONTAP: vserver cifs share show -vserver <svm> -fields path"
                            if i == 0 else None))
        if not name:
            if not shares:
                ui.emit("      add at least one share", ui.YELLOW)
                if not ui.interactive:
                    raise SystemExit("--non-interactive: no shares for " + vserver)
                continue
            break
        spath = ui.ask(f"    namespace path of {name}", d_path or f"/{name}", v_ns_path)
        if scan_root != "/" and not (spath == scan_root or spath.startswith(scan_root + "/")):
            ui.emit(f"      {spath} is outside the scan$ path {scan_root}; not added", ui.YELLOW)
            continue
        shares[name] = spath
        i += 1
    return {"vserver": vserver, "cifs_server": cifs, "host": host, "scan_share": scan_share,
            "scan_root": scan_root, "mnt": mnt, "smb_version": vers, "user": user,
            "domain": dom, "password": password, "shares": shares}


def collect(ui, facts, prev):
    ui.phase(2, 4, "Questions (nothing is changed yet)")
    ui.note("Press Enter to accept the value in [brackets]. Defaults come from the previous "
            "run when there was one.")
    plan = {}

    ui.section("Software and signatures")
    plan["proxy"] = ui.ask("HTTP proxy for downloads (blank = none)", prev.get("proxy", ""),
                           v_proxy, allow_empty=True,
                           help="Only if this host reaches the internet through a proxy. "
                                "EC2 instances with an internet or NAT gateway don't need one.")
    plan["freshclam"] = ui.ask_yes(
        "Download the official ClamAV signatures with freshclam?",
        prev.get("freshclam", facts.get("cdn_ok", False)),
        help="Needs HTTPS to database.clamav.net (~350 MB, about 1.5 GB RAM in clamd). "
             "Without it only the lab EICAR signature is loaded.")
    plan["lab_signature"] = ui.ask_yes(
        "Install the lab EICAR signature (matches EICAR anywhere in a file)?",
        prev.get("lab_signature", True),
        help="The official EICAR signature only matches the exact 68-byte file; the lab one "
             "also catches EICAR inside bigger files (large-file tests).")

    ui.section("SVMs and shares")
    svms = []
    prev_svms = prev.get("svms") or []
    if prev_svms and ui.ask_yes(f"Reuse the {len(prev_svms)} SVM entr"
                                f"{'y' if len(prev_svms) == 1 else 'ies'} from the previous "
                                f"answers ({', '.join(s['vserver'] for s in prev_svms)})?", True):
        for s in prev_svms:
            s = dict(s)
            ui.say(f"SVM {s['vserver']}: //{s['host']}/{s['scan_share']} -> {s['mnt']}, "
                   f"shares {', '.join(s['shares'])}")
            s["password"] = ui.ask_secret(f"password for {s['domain']}\\{s['user']}",
                                          (env_key(s["vserver"]), "FPAV_SVM_PASSWORD"))
            svms.append(s)
    else:
        i = 0
        while True:
            svms.append(ask_svm(ui, prev_svms[i] if i < len(prev_svms) else None))
            i += 1
            if not ui.ask_yes("Add another SVM?", i < len(prev_svms)):
                break
    mounts = [s["mnt"] for s in svms]
    if len(set(mounts)) != len(mounts):
        raise SystemExit("two SVMs use the same mount point; run the wizard again")
    plan["svms"] = svms

    ui.section("Shared verdict cache")
    pc = prev.get("cache") or {}
    use = ui.ask_yes("Use a shared Redis/Valkey verdict cache?", pc.get("backend", "none") != "none",
                     help="Optional. With several scanners it lets one scan serve all of them and "
                          "survives restarts. Set the cache up first with setup_cache.py. Without "
                          "it each scanner keeps its own in-memory cache.")
    cache = {"backend": "none"}
    if use:
        cache["backend"] = ui.ask_choice("Cache engine", ["valkey", "redis"],
                                         pc.get("backend") if pc.get("backend") in ("valkey", "redis")
                                         else "valkey")
        mode = ui.ask_choice("Connect directly or through Sentinel", ["direct", "sentinel"],
                             pc.get("mode", "direct"),
                             help="Sentinel finds the current primary after a failover.")
        cache["mode"] = mode
        if mode == "sentinel":
            cache["sentinel"] = ui.ask("Sentinel servers host:port, comma-separated",
                                       pc.get("sentinel"), v_host_list)
            cache["sentinel_master"] = ui.ask("Monitored primary name",
                                              pc.get("sentinel_master", "fpolicy-cache"))
        else:
            cache["host"] = ui.ask("Cache host", pc.get("host"), v_host)
            cache["port"] = ui.ask("Cache port", pc.get("port", 6379), v_port)
        cache["ttl_seconds"] = ui.ask_int("Verdict time-to-live (seconds)",
                                          pc.get("ttl_seconds", 86400), 60, 31536000)
        cache["password"] = ui.ask_secret("Cache password (blank if none)",
                                          ("FPAV_CACHE_PASSWORD",), allow_empty=True)
    plan["cache"] = cache

    ui.section("Scanner behaviour")
    ps = prev.get("server") or {}
    srv = {}
    srv["sync_limit_mb"] = ui.ask_int(
        f"Scan-while-held size limit in MB (1-{SYNC_LIMIT_MAX_MB})",
        ps.get("sync_limit_mb", SYNC_LIMIT_MAX_MB), 1, SYNC_LIMIT_MAX_MB,
        help="Opens of files up to this size wait for the scan. Bigger files are allowed at "
             "once and scanned in the background; the next open is denied if infected.")
    srv["sync_deadline_s"] = ui.ask_int(
        "Answer ONTAP after at most N seconds (5-19)", ps.get("sync_deadline_s", 15), 5, 19,
        help="ONTAP cancels a screen request after 20 s. If a scan isn't done by then, the "
             "scanner answers by the fail mode and finishes the scan in the background.")
    closed = ui.ask_yes("Fail closed (deny when the scanner can't decide)?",
                        ps.get("fail_mode", "open") == "closed",
                        help="Open = allow when clamd is down or a file can't be read. Must match "
                             "ONTAP: -is-mandatory true for closed, false for open.")
    srv["fail_mode"] = "closed" if closed else "open"
    srv["bind"] = ui.ask("Listen address", ps.get("bind", "0.0.0.0"), v_host)
    srv["port"] = ui.ask("Listen port", ps.get("port", 9898), v_port)
    cpus = facts.get("cpus", 2)
    srv["workers"] = ui.ask_int("Screen worker threads", ps.get("workers", 16), 2, 256)
    srv["bg_workers"] = ui.ask_int("Background scan threads", ps.get("bg_workers", max(2, cpus // 2)),
                                   1, 64)
    srv["allowed_clients"] = ui.ask(
        "Accept FPolicy connections only from (IPs/CIDRs, blank = any)",
        ps.get("allowed_clients", ""), v_ip_list, allow_empty=True,
        help="The SVM data LIFs ONTAP connects from (LIFs whose service policy includes "
             "data-fpolicy-client). A wrong list makes ONTAP fail to connect, so leave it "
             "blank first and restrict with the security group; tighten it later.")
    plan["server"] = srv

    ui.section("This host")
    plan["scanner_ip"] = ui.ask("This scanner's IP address as ONTAP reaches it",
                                facts.get("ip") or prev.get("scanner_ip"), v_host,
                                help="Defaults to this host's private IP (answers copied from "
                                     "another scanner don't override it).")
    plan["fstab"] = ui.ask_yes("Add the scan$ mounts to /etc/fstab (remount at boot)?",
                               prev.get("fstab", True))
    plan["service"] = ui.ask_yes("Install and start the fpolicy-av service?",
                                 prev.get("service", True))
    plan["firewall"] = False
    if facts.get("ufw_active"):
        plan["firewall"] = ui.ask_yes(f"ufw is active: allow TCP {srv['port']} from the FPolicy "
                                      f"clients?", prev.get("firewall", True))
    return plan


# ============================================================== PHASE 3 =====
def mount_opts(s, for_fstab):
    opts = ["ro", f"vers={s['smb_version']}",
            f"credentials={os.path.join(CRED_DIR, s['vserver'] + '.cred')}",
            f"uid={SVC_USER}", f"gid={SVC_USER}", "file_mode=0440", "dir_mode=0550",
            "cache=none", "actimeo=0", "noserverino"]
    if for_fstab:
        opts += ["_netdev", "nofail", "x-systemd.mount-timeout=30s"]
    return ",".join(opts)


def local_share_path(s, spath):
    rel = os.path.relpath(spath, s["scan_root"]) if s["scan_root"] != "/" else spath.lstrip("/")
    return os.path.normpath(os.path.join(s["mnt"], rel)) if rel not in ("", ".") else s["mnt"]


def ontap_scan_share_cmds(s):
    v, sh = s["vserver"], s["scan_share"]
    acct = f"{s['domain']}\\{s['user']}"
    return [
        f"vserver cifs share create -vserver {v} -share-name {sh} -path {s['scan_root']}",
        f"vserver cifs share access-control delete -vserver {v} -share {sh} -user-or-group Everyone",
        f"vserver cifs share access-control create -vserver {v} -share {sh} "
        f"-user-or-group \"{acct}\" -permission Read",
        f"vserver cifs share modify -vserver {v} -share-name {sh} -vscan-fileop-profile no-scan",
    ]


def ontap_text(plan):
    srv = plan["server"]
    mandatory = "true" if srv["fail_mode"] == "closed" else "false"
    ip, port = plan["scanner_ip"], srv["port"]
    out = [f"# ONTAP commands generated by {WIZARD}.py {WIZARD_VERSION} on "
           f"{datetime.datetime.now():%Y-%m-%d %H:%M}",
           "# Run them on the cluster that owns the cache SVM (FSx: ssh fsxadmin@<management "
           "endpoint>).",
           "# Nothing here was applied by the wizard.", ""]
    for s in plan["svms"]:
        v, shares = s["vserver"], ",".join(s["shares"])
        out += [f"# ======== SVM {v} ========",
                "# 1. scan$: hidden, read-only for the scanner account, never virus-scanned"]
        out += ontap_scan_share_cmds(s)
        out += ["#    The account also needs NTFS read access to the files it scans.", "",
                "# 2a. NEW FPolicy setup",
                f"vserver fpolicy policy external-engine create -vserver {v} -engine-name av_engine "
                f"-primary-servers {ip} -port {port} -extern-engine-type synchronous "
                f"-ssl-option no-auth -extern-engine-format xml",
                f"vserver fpolicy policy event create -vserver {v} -event-name av_open "
                f"-protocol cifs -file-operations open -filters exclude-directory",
                f"vserver fpolicy policy event create -vserver {v} -event-name av_close "
                f"-protocol cifs -file-operations close -filters close-with-modification,"
                f"exclude-directory",
                f"vserver fpolicy policy create -vserver {v} -policy-name av_pol "
                f"-events av_open,av_close -engine av_engine -is-mandatory {mandatory}",
                f"vserver fpolicy policy scope create -vserver {v} -policy-name av_pol "
                f"-shares-to-include {shares}",
                f"vserver fpolicy enable -vserver {v} -policy-name av_pol -sequence-number 1", "",
                "# 2b. EXISTING av_engine (add this scanner; list every scanner IP)",
                f"vserver fpolicy disable -vserver {v} -policy-name av_pol",
                f"vserver fpolicy policy external-engine modify -vserver {v} -engine-name av_engine "
                f"-primary-servers {ip},<other scanner IPs> -port {port}",
                f"vserver fpolicy policy modify -vserver {v} -policy-name av_pol "
                f"-is-mandatory {mandatory}",
                f"vserver fpolicy enable -vserver {v} -policy-name av_pol -sequence-number 1", "",
                "# 3. Check",
                f"vserver fpolicy show-engine -vserver {v}",
                f"vserver fpolicy show -vserver {v}",
                f"network interface show -vserver {v} -fields address,service-policy",
                "#    FPolicy connects from data LIFs whose service policy includes "
                "data-fpolicy-client.", ""]
    out += ["# ======== AWS security groups (EC2 + FSx for ONTAP) ========",
            f"# scanner SG   inbound TCP {port} from the SVM data LIF IPs (FSx Endpoints tab;"
            " Multi-AZ endpoints",
            "#              use the endpoint IP address range) or from the FSx file system's SG",
            "# FSx SG       inbound TCP 445 from the scanner SG (scan$ mount)"]
    if plan["cache"]["backend"] != "none":
        out += ["# cache SG     inbound TCP 6379 (and 26379 with Sentinel) from the scanner SG"]
    out += ["# scanner SG   outbound: 445 to the SVM, 443 to database.clamav.net, 80/443 to the "
            "Ubuntu mirror", ""]
    return "\n".join(out) + "\n"


def summary(ui, plan, facts):
    ui.phase(3, 4, "Summary (nothing is changed yet)")
    ui.section("What will be configured")
    ui.kv("proxy", plan["proxy"] or "none")
    ui.kv("signatures", ("official (freshclam)" if plan["freshclam"] else "no official") +
          (" + lab EICAR" if plan["lab_signature"] else ""))
    for s in plan["svms"]:
        ui.kv(f"SVM {s['vserver']}", f"//{s['host']}/{s['scan_share']} -> {s['mnt']} "
                                     f"(SMB {s['smb_version']}, {s['domain']}\\{s['user']})")
        for name, spath in s["shares"].items():
            ui.kv(f"  share {name}", f"{spath} -> {local_share_path(s, spath)}")
    c = plan["cache"]
    if c["backend"] == "none":
        ui.kv("verdict cache", "local only")
    else:
        target = c.get("sentinel") if c.get("mode") == "sentinel" else f"{c['host']}:{c['port']}"
        ui.kv("verdict cache", f"{c['backend']} {c.get('mode')} {target}, TTL {c['ttl_seconds']} s")
    srv = plan["server"]
    ui.kv("listen", f"{srv['bind']}:{srv['port']} (ONTAP connects to {plan['scanner_ip']})")
    ui.kv("sync limit / deadline", f"{srv['sync_limit_mb']} MB / {srv['sync_deadline_s']} s")
    ui.kv("fail mode", f"{srv['fail_mode']} (ONTAP -is-mandatory "
                       f"{'true' if srv['fail_mode'] == 'closed' else 'false'})")
    ui.kv("workers", f"{srv['workers']} screen, {srv['bg_workers']} background")
    ui.kv("allowed FPolicy clients", srv["allowed_clients"] or "any")
    ui.kv("fstab / service / ufw", f"{'yes' if plan['fstab'] else 'no'} / "
                                   f"{'yes' if plan['service'] else 'no'} / "
                                   f"{'yes' if plan['firewall'] else 'no'}")
    ui.section("ONTAP prerequisite: create scan$ BEFORE the mount step")
    ui.note("The mount step fails if the share doesn't exist yet. Run these on the cluster now "
            "if you haven't (all ONTAP commands are also printed and saved at the end):")
    for s in plan["svms"]:
        ui.block("\n".join(ontap_scan_share_cmds(s)), prefix="    ")


# ============================================================== PHASE 4 =====
def clamd_settings(plan, facts):
    threads = max(8, plan["server"]["workers"] + plan["server"]["bg_workers"])
    st = {
        "LocalSocket": CLAMD_SOCK,
        "LocalSocketGroup": "clamav",
        "LocalSocketMode": "660",
        "FixStaleSocket": "true",
        "StreamMaxLength": f"{SYNC_LIMIT_MAX_MB}M",
        "MaxFileSize": "2000M",
        "MaxScanSize": "2000M",
        "MaxScanTime": "600000",
        "MaxThreads": str(min(threads, 64)),
        "EnableVersionCommand": "true",
    }
    if facts.get("mem_mb", 0) and facts["mem_mb"] < 3800:
        st["ConcurrentDatabaseReload"] = "false"
    return st


WHY_CLAMD = {
    "LocalSocket": "UNIX socket: needed for fdpass",
    "LocalSocketGroup": "the fpolicy-av user joins this group",
    "LocalSocketMode": "only root and the clamav group may connect",
    "FixStaleSocket": "remove a stale socket after a crash",
    "StreamMaxLength": "INSTREAM fallback cap",
    "MaxFileSize": "Ubuntu default 25M would skip bigger files",
    "MaxScanSize": "Ubuntu default 100M",
    "MaxScanTime": "10 min for large background scans",
    "MaxThreads": "screen + background workers",
    "EnableVersionCommand": "Ubuntu default false; the cache key needs it",
    "ConcurrentDatabaseReload": "less than 4 GB RAM: don't load 2 databases at once",
}


def edit_clamd_conf(text, settings):
    """Set directives in place (first occurrence), drop duplicates, append missing."""
    seen, out, changes = set(), [], []
    for line in text.splitlines():
        key = line.split()[0] if line.strip() and not line.lstrip().startswith("#") else None
        if key in settings:
            old = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if key in seen:
                continue
            seen.add(key)
            if old != settings[key]:
                changes.append((key, old, settings[key]))
            out.append(f"{key} {settings[key]}")
        elif line.strip() == "Example":
            continue
        else:
            out.append(line)
    missing = [k for k in settings if k not in seen]
    if missing:
        out.append("# added by the fpolicy-av wizard")
        for k in missing:
            out.append(f"{k} {settings[k]}")
            changes.append((k, "(not set)", settings[k]))
    return "\n".join(out) + "\n", changes


def step_proxy(ui, plan, facts):
    if not plan["proxy"]:
        if os.path.exists(APT_PROXY_CONF):
            ui.remove_path(APT_PROXY_CONF)
        ui.skip("no proxy configured")
        return "skip"
    ui.write_file(APT_PROXY_CONF, f'Acquire::http::Proxy "{plan["proxy"]}";\n'
                                  f'Acquire::https::Proxy "{plan["proxy"]}";\n')
    os.environ["http_proxy"] = os.environ["https_proxy"] = plan["proxy"]
    ui.ok("apt will use the proxy")


# Timeouts so a host without internet fails fast; wait up to 10 min for the dpkg lock
# (unattended-upgrades often holds it right after boot); keep edited config files
# on package upgrades instead of prompting.
APT_OPTS = ["-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30",
            "-o", "Acquire::Retries=2", "-o", "Dpkg::Use-Pty=0",
            "-o", "DPkg::Lock::Timeout=600",
            "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


def step_apt_update(ui, plan, facts):
    ui.note("Timeouts are set so a host without internet access fails in about a minute "
            "instead of hanging.")
    ui.run(["apt-get"] + APT_OPTS + ["update"], env=APT_ENV, timeout=600)
    ui.ok("package index refreshed")


def step_packages(ui, plan, facts):
    for p, why in (("clamav-daemon", "clamd, the scanning daemon"),
                   ("clamav-freshclam", "freshclam, the signature updater"),
                   ("clamav, clamdscan", "command-line scanners (for manual tests)"),
                   ("cifs-utils, keyutils", "mount.cifs and its helpers, to mount scan$"),
                   ("python3-redis", "Redis/Valkey client for the shared cache"),
                   ("ca-certificates", "HTTPS to the signature CDN")):
        ui.kv(p, why)
    ui.run(["apt-get"] + APT_OPTS + ["install", "-y"] + PACKAGES,
           env=APT_ENV, timeout=1800)
    rc, out = ui.probe(["dpkg-query", "-W", "-f", "${Package} ${Version}\n"] + PACKAGES)
    ui.say("package versions now installed:")
    ui.block(out)
    ui.note("The package starts clamav-freshclam, which begins downloading signatures in the "
            "background right away. clamd itself is configured and started in later steps.")
    ui.ok("packages installed")


def step_cifs(ui, plan, facts):
    rc, out = ui.probe(["modinfo", "-F", "filename", "cifs"])
    if rc != 0:
        rel = os.uname().release
        ui.warn(f"cifs.ko not found for kernel {rel}; installing linux-modules-extra-{rel}")
        ui.run(["apt-get"] + APT_OPTS + ["install", "-y", f"linux-modules-extra-{rel}"],
               env=APT_ENV, timeout=900)
    ui.run(["modprobe", "cifs"], check=False)
    rc, out = ui.probe(["modinfo", "-F", "version", "cifs"])
    ui.ok(f"kernel SMB client ready (cifs module version {out or 'n/a'})")


def step_user(ui, plan, facts):
    ui.note(f"The service runs as the unprivileged user {SVC_USER}. The scan$ mounts are "
            f"readable only by this user (and root), and it joins the clamav group to reach "
            f"the clamd socket.")
    rc, _ = ui.probe(["id", SVC_USER])
    if rc == 0:
        ui.say(f"user {SVC_USER} already exists")
    else:
        ui.run(["useradd", "--system", "--home-dir", SVC_HOME, "--create-home",
                "--shell", "/usr/sbin/nologin", "--comment", "FPolicy AV scanner", SVC_USER])
    ui.run(["usermod", "-a", "-G", "clamav", SVC_USER])
    ui.run(["id", SVC_USER], changes=False, check=False)
    ui.mkdir(LOG_DIR, 0o750, (SVC_USER, SVC_USER))
    ui.ok(f"service account {SVC_USER} ready")


def step_clamd_config(ui, plan, facts):
    settings = clamd_settings(plan, facts)
    text = read_text(CLAMD_CONF)
    if not text and not ui.dry_run:
        raise StepError(f"{CLAMD_CONF} not found: is clamav-daemon installed?")
    new, changes = edit_clamd_conf(text, settings)
    ui.say(f"{CLAMD_CONF}: directives the scanner depends on")
    for key, old, val in changes:
        ui.kv(key, f"{old} -> {val}   ({WHY_CLAMD.get(key, '')})")
    for key in settings:
        if key not in [c[0] for c in changes]:
            ui.kv(key, f"{settings[key]} (already set)")
    ui.write_file(CLAMD_CONF, new, 0o644, show="none")

    ui.say("systemd drop-ins: Ubuntu's clamav-daemon units only start when main.cvd and "
           "daily.cvd exist; these let clamd start with the lab signature alone.")
    dropin = ("# fpolicy-av: start even when only the offline lab signature exists.\n"
              "# An empty Condition line clears the package's database-existence checks.\n"
              "[Unit]\nConditionPathExistsGlob=\n")
    for path in CLAMD_DROPINS:
        ui.write_file(path, dropin)

    mounts = sorted({s["mnt"] for s in plan["svms"]})
    if os.path.exists(APPARMOR_PROFILE):
        ui.say("AppArmor: Ubuntu confines clamd. Files passed with fdpass are re-checked "
               "against its profile, so clamd needs read access to the mount points.")
        rules = [f"{m}/** r," for m in mounts] + [f"{m}/ r," for m in mounts]
        cur = read_text(APPARMOR_LOCAL)
        ui.write_file(APPARMOR_LOCAL, managed_block(cur, "fpolicy-av scan$ mounts", rules),
                      0o644, show="diff" if cur else "content")
        enabled = read_text("/sys/module/apparmor/parameters/enabled").strip() == "Y"
        parser = shutil.which("apparmor_parser") or ("/sbin/apparmor_parser"
                                                      if os.path.exists("/sbin/apparmor_parser")
                                                      else None)
        if enabled and parser:
            ui.run([parser, "-r", APPARMOR_PROFILE])
            ui.ok("clamd AppArmor profile reloaded with the mount rules")
        else:
            ui.skip("AppArmor is not active (or apparmor_parser missing): profile not reloaded")
    else:
        ui.skip(f"{APPARMOR_PROFILE} not present; no AppArmor change needed")
    ui.run(["systemctl", "daemon-reload"])
    ui.ok("clamd configured")


def step_signatures(ui, plan, facts):
    if plan["proxy"]:
        m = re.match(r"https?://([^:/]+):(\d+)", plan["proxy"])
        text, _ = edit_clamd_conf(read_text(FRESHCLAM_CONF),
                                  {"HTTPProxyServer": m.group(1), "HTTPProxyPort": m.group(2)})
        ui.write_file(FRESHCLAM_CONF, text, 0o644, show="diff")
    got_official = False
    if plan["freshclam"] and ui.dry_run:
        ui.run(["systemctl", "stop", "clamav-freshclam"], check=False)
        ui.run(["freshclam", "--stdout"], check=False)
        ui.run(["systemctl", "enable", "--now", "clamav-freshclam"], check=False)
        got_official = True
    elif plan["freshclam"]:
        ui.note("freshclam can't run while the clamav-freshclam service holds its lock, so the "
                "service is stopped for the manual update and started again afterwards.")
        ui.run(["systemctl", "stop", "clamav-freshclam"], check=False)
        r = ui.run(["freshclam", "--stdout"], check=False, timeout=1200)
        ui.run(["systemctl", "enable", "--now", "clamav-freshclam"], check=False)
        got_official = r.ok or bool(glob.glob(os.path.join(CLAMD_DB, "daily.c[vl]d")))
        if got_official:
            ui.ok("official signatures present")
        else:
            ui.warn("freshclam failed (see its output above). Common causes: no HTTPS to "
                    "database.clamav.net, a proxy, or the CDN rate limit (try again in an hour).")
    if plan["lab_signature"] or not got_official:
        if not plan["lab_signature"]:
            ui.warn("no official signatures: installing the lab EICAR signature so clamd can "
                    "start")
        ui.write_file(LAB_SIG, f"Lab.EICAR-Test-File:0:*:{EICAR_HEX}\n", 0o644,
                      owner=("clamav", "clamav") if not ui.dry_run else None)
    ui.say(f"signature files in {CLAMD_DB}:")
    for f in sorted(glob.glob(os.path.join(CLAMD_DB, "*"))):
        if os.path.isfile(f):
            ui.kv(os.path.basename(f), f"{os.path.getsize(f) / 1048576:.1f} MB")
    ui.ok("signatures ready")


def step_clamd_start(ui, plan, facts):
    fav = load_server_module()
    ui.run(["systemctl", "enable", "clamav-daemon.socket", "clamav-daemon.service"], check=False)
    ui.run(["systemctl", "stop", "clamav-daemon.service"], check=False)
    ui.run(["systemctl", "restart", "clamav-daemon.socket"])
    ui.run(["systemctl", "start", "clamav-daemon.service"])
    if ui.dry_run:
        ui.skip("dry run: not waiting for clamd")
        return "skip"
    scanner = fav.Scanner(CLAMD_SOCK, "127.0.0.1", None, 100 * 1024 * 1024,
                          builtin_fallback=False)
    ui.say("waiting for clamd to load its database (the full database takes 20-90 s) ...")
    t0 = time.time()
    last = 0
    while not scanner.ping(timeout=5):
        if time.time() - t0 > 420:
            ui.run(["systemctl", "status", "clamav-daemon", "--no-pager", "-l", "-n", "30"],
                   check=False, changes=False)
            raise StepError("clamd did not answer PING within 7 minutes")
        if time.time() - last >= 10:
            last = time.time()
            ui.say(f"  ... {time.time() - t0:.0f} s")
        time.sleep(2)
    ui.ok(f"clamd answers PING after {time.time() - t0:.0f} s")
    ver = scanner.version()
    (ui.ok if ver != "unknown" else ui.warn)(f"clamd VERSION: {ver}")
    rc, out = ui.probe(["ps", "-C", "clamd", "-o", "rss="])
    if out.strip():
        ui.kv("clamd memory (RSS)", f"{int(out.split()[0]) // 1024} MB")
    tmp = tempfile.mkdtemp(prefix="fpav-eicar-")
    try:
        for label, data, expect in (("EICAR", fav.EICAR, True), ("clean", b"hello\n", False)):
            p = os.path.join(tmp, f"{label}.txt")
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o755)
            for method in ("fdpass", "INSTREAM"):
                try:
                    if method == "fdpass":
                        inf, sig, eng = scanner.scan_fd(p, 30)
                    else:
                        inf, sig, eng = scanner.scan_instream(p, 30)
                except (OSError, RuntimeError) as e:
                    raise StepError(f"{method} scan of the {label} test file failed: {e}")
                res = f"FOUND {sig}" if inf else "clean"
                if inf == expect:
                    ui.ok(f"{method:<8} {label} test file -> {res}")
                else:
                    raise StepError(f"{method} {label} test file -> {res} (unexpected)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ui.run(["systemctl", "--no-pager", "-n", "0", "status", "clamav-daemon"],
           check=False, changes=False)


def step_creds(ui, plan, facts):
    ui.mkdir(CONF_DIR, 0o750, ("root", SVC_USER) if not ui.dry_run else None)
    ui.mkdir(CRED_DIR, 0o700, ("root", "root"))
    for s in plan["svms"]:
        ui.write_file(os.path.join(CRED_DIR, s["vserver"] + ".cred"),
                      f"username={s['user']}\npassword={s['password']}\ndomain={s['domain']}\n",
                      0o600, ("root", "root"))
    ui.ok("credentials stored (root only; mount.cifs reads them, the password never appears "
          "on a command line)")


def step_network(ui, plan, facts):
    bad = False
    for s in plan["svms"]:
        ips = resolve_host(s["host"])
        if ips:
            ui.ok(f"{s['host']} resolves to {', '.join(ips)}")
        else:
            ui.fail(f"{s['host']} does not resolve (DNS)")
            bad = True
            continue
        ok, ms, err = tcp_check(s["host"], 445, 5)
        if ok:
            ui.ok(f"TCP 445 to {s['host']} open ({ms:.0f} ms)")
        else:
            ui.fail(f"TCP 445 to {s['host']}: {err}")
            ui.note("Check the FSx/SVM security group (inbound TCP 445 from this instance), "
                    "the route to the SVM, and the address.")
            bad = True
    if bad:
        raise StepError("an SVM is not reachable on TCP 445")


MOUNT_HINTS = {
    "13": "Permission denied: wrong user/password/domain, or the account has no permission on "
          "scan$ (vserver cifs share access-control show -share scan$).",
    "2": "No such file or directory: the scan$ share doesn't exist yet (see the ONTAP "
         "prerequisite in the summary) or the share name is wrong.",
    "95": "Operation not supported: try another SMB dialect (3.0).",
    "112": "Host is down: network path or security group.",
    "113": "No route to host: routing or security group.",
    "110": "Timed out: network path or security group.",
    "111": "Connection refused: nothing listens on 445 at that address.",
    "115": "Operation in progress: network path or security group.",
}

SAMPLE_READ = r"""
import os, sys
ok = bad = 0
for root, dirs, files in os.walk(sys.argv[1]):
    for n in files:
        p = os.path.join(root, n)
        try:
            with open(p, 'rb') as f: f.read(1)
            ok += 1
        except OSError as e:
            bad += 1
            if bad <= 3: print('cannot read', p, '-', e)
        if ok + bad >= 20: break
    if ok + bad >= 20: break
print(f'read test: {ok} readable, {bad} not readable (sampled up to 20 files)')
sys.exit(1 if bad and not ok else 0)
"""


def step_mount(ui, plan, facts):
    failed = []
    rc, out = ui.probe(["systemctl", "is-active", SERVICE])
    if out.strip() == "active":
        ui.say(f"{SERVICE} is running from an earlier install: stopping it so the mounts can be "
               f"replaced (it is started again in a later step)")
        ui.run(["systemctl", "stop", SERVICE], check=False)
    for s in plan["svms"]:
        unc = f"//{s['host']}/{s['scan_share']}"
        ui.section(f"{unc} -> {s['mnt']}")
        ui.mkdir(s["mnt"], 0o755)
        opts = mount_opts(s, for_fstab=False)
        ui.note("Options: ro = read-only; credentials = root-only file; uid/gid/file_mode/"
                "dir_mode = only the fpolicy-av user can read; cache=none,actimeo=0 = every "
                "stat() returns the current size and mtime (no stale verdicts); noserverino = "
                "stable inode numbers on SMB.")
        if os.path.ismount(s["mnt"]):
            ui.say(f"{s['mnt']} is already mounted: remounting with the current options")
            if not ui.run(["umount", s["mnt"]], check=False).ok and os.path.ismount(s["mnt"]):
                ui.warn(f"{s['mnt']} is busy and stays mounted with its old options")
                continue
        r = ui.run(["mount", "-t", "cifs", unc, s["mnt"], "-o", opts], check=False, timeout=60)
        if not r.ok:
            m = re.search(r"mount error\((\d+)\)", r.out)
            hint = MOUNT_HINTS.get(m.group(1) if m else "", "see the kernel messages below")
            ui.fail(f"mount failed: {hint}")
            ui.run("dmesg 2>/dev/null | grep -i cifs | tail -n 12", check=False, changes=False)
            failed.append(unc)
            continue
        if ui.dry_run:
            continue
        ui.run(["findmnt", "-T", s["mnt"], "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
               check=False, changes=False)
        ui.run(["runuser", "-u", SVC_USER, "--", "ls", "-la", s["mnt"]], check=False,
               changes=False)
        for name, spath in s["shares"].items():
            local = local_share_path(s, spath)
            if os.path.isdir(local):
                ui.ok(f"share {name}: {local} exists")
                r2 = ui.run(["runuser", "-u", SVC_USER, "--", sys.executable, "-c",
                             SAMPLE_READ, local], check=False, changes=False, quiet_cmd=True)
                if not r2.ok:
                    ui.warn(f"the account can't read files under {local}: grant it NTFS read "
                            f"access")
            else:
                ui.fail(f"share {name}: {local} not found under the mount (check the share's "
                        f"namespace path: vserver cifs share show -share-name {name} -fields path)")
                failed.append(f"{name} path")
    if failed:
        raise StepError("mount problems: " + ", ".join(failed))


def step_fstab(ui, plan, facts):
    lines = [f"//{s['host']}/{s['scan_share']}\t{s['mnt']}\tcifs\t{mount_opts(s, True)}\t0\t0"
             for s in plan["svms"]]
    ui.note("_netdev = mount after the network is up; nofail = boot neither waits for nor "
            "fails on an unreachable SVM; x-systemd.mount-timeout = give up after 30 s.")
    cur = read_text("/etc/fstab")
    ui.write_file("/etc/fstab", managed_block(cur, "fpolicy-av scan$ mounts", lines), 0o644,
                  show="diff")
    ui.run(["systemctl", "daemon-reload"])
    ui.say("syntax check of the new lines (findmnt --verify on a copy holding only them):")
    fd, tmp = tempfile.mkstemp(prefix="fpav-fstab-")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    ui.run(["findmnt", "--verify", "--verbose", "--tab-file", tmp], check=False, changes=False)
    os.unlink(tmp)
    ui.say("proving the fstab lines work: unmount, then mount by mount point (reads /etc/fstab)")
    for s in plan["svms"]:
        if not ui.run(["umount", s["mnt"]], check=False).ok and os.path.ismount(s["mnt"]):
            ui.warn(f"{s['mnt']} is busy: fstab remount test skipped")
            continue
        ui.run(["mount", s["mnt"]], timeout=60)
        if not ui.dry_run:
            ui.run(["findmnt", "-T", s["mnt"], "-o", "TARGET,SOURCE,FSTYPE"], check=False,
                   changes=False)
    ui.ok("mounts persist across reboots")


def step_cache(ui, plan, facts):
    c = plan["cache"]
    if c["backend"] == "none":
        ui.skip("no shared cache: verdicts stay in this scanner's memory")
        return "skip"
    if ui.dry_run:
        ui.skip("dry run: not connecting")
        return "skip"
    fav = load_server_module()
    cfg = {k: str(v) for k, v in c.items() if k != "mode"}
    t0 = time.time()
    vc = fav.VerdictCache(cfg)
    ui.kv("connect", f"{(time.time() - t0) * 1000:.0f} ms: {vc.describe()}")
    if vc.redis is None:
        ui.warn("the cache is unreachable. The scanner still works (local cache only) and "
                "keeps retrying every 30 s. Check the cache SG (TCP 6379/26379), the address "
                "and the password.")
        return
    try:
        info = vc.redis.info("replication")
        ui.kv("role", f"{info.get('role')} (connected replicas: "
                      f"{info.get('connected_slaves', '-')})")
        if info.get("role") not in ("master", None):
            ui.warn("this is a read-only replica: point the scanners at the primary, or use "
                    "Sentinel")
            return
        vc.redis.set("verdict:__fpav_setup_test__", "0:", ex=60)
        ui.kv("write/read test", "ok" if vc.redis.get("verdict:__fpav_setup_test__") else "failed")
    except Exception as e:
        ui.warn(f"cache test failed ({e.__class__.__name__}: {e}); the scanner still works "
                f"with its local cache")
        return
    ui.ok("shared verdict cache reachable")


def scanner_conf_text(plan):
    srv = plan["server"]
    lines = ["# fpolicy_av_linux.py configuration, written by setup_scanner.py "
             f"{WIZARD_VERSION} on {datetime.datetime.now():%Y-%m-%d %H:%M}",
             "[server]",
             f"bind = {srv['bind']}", f"port = {srv['port']}",
             f"sync_limit_mb = {srv['sync_limit_mb']}",
             f"sync_deadline_s = {srv['sync_deadline_s']}",
             f"fail_mode = {srv['fail_mode']}",
             "allow_code = 1", "deny_code = 2",
             f"workers = {srv['workers']}", f"bg_workers = {srv['bg_workers']}",
             "bg_timeout_s = 900",
             f"allowed_clients = {srv['allowed_clients']}",
             "stats_interval_s = 300", "sigver_refresh_s = 300", "raw_dump = 10",
             "require_cifs_mount = true", "probe_codes = false",
             f"log = {LOG_DIR}/fpolicy_av.log", "log_level = info", "",
             "[clamd]", f"socket = {CLAMD_SOCK}", "", "[cache]"]
    c = plan["cache"]
    lines += [f"{k} = {v}" for k, v in c.items() if k != "mode" and v != ""]
    lines += ["", "[shares]",
              "# <CIFS server>/<share> = folder holding the same files under the scan$ mount"]
    for s in plan["svms"]:
        for name, spath in s["shares"].items():
            lines.append(f"{s['cifs_server'].lower()}/{name.lower()} = {local_share_path(s, spath)}")
    return "\n".join(lines) + "\n"


def step_config(ui, plan, facts):
    ui.write_file(CONF, scanner_conf_text(plan), 0o640,
                  ("root", SVC_USER) if not ui.dry_run else None)
    ui.ok(f"{CONF} written (readable by root and {SVC_USER}; it may hold the cache password)")


def step_install_server(ui, plan, facts):
    ui.mkdir(OPT_DIR, 0o755)
    ui.say(f"copy {SERVER_SRC} -> {SERVER_DST}")
    if not ui.dry_run:
        shutil.copy2(SERVER_SRC, SERVER_DST)
        os.chmod(SERVER_DST, 0o755)
        readme = os.path.join(HERE, "README.md")
        if os.path.exists(readme):
            shutil.copy2(readme, os.path.join(OPT_DIR, "README.md"))
    ui.say(f"health check as {SVC_USER} (the same user the service runs as):")
    r = ui.run(["runuser", "-u", SVC_USER, "--", sys.executable, SERVER_DST, "--config", CONF,
                "--check"], check=False, changes=ui.dry_run)
    if not r.ok and not ui.dry_run:
        raise StepError("health check failed (FAIL lines above)")
    ui.ok("server installed and healthy")


def mount_unit(path):
    """systemd unit name of a mount point, e.g. mnt-fpolicy\\x2dav-svm1.mount."""
    try:
        out = subprocess.run(["systemd-escape", "--path", "--suffix=mount", path],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        if out:
            return out
    except (OSError, subprocess.TimeoutExpired):
        pass
    esc = "".join(c if c.isalnum() or c in "_." else f"\\x{ord(c):02x}"
                  for c in path.strip("/")).replace("\\x2f", "-")
    return esc + ".mount"


def unit_text(plan):
    mounts = " ".join(mount_unit(s["mnt"]) for s in plan["svms"]) if plan["fstab"] else ""
    return textwrap.dedent(f"""\
        # Written by setup_scanner.py {WIZARD_VERSION}
        [Unit]
        Description=ONTAP FPolicy antivirus scanner (lab, fpolicy_av_linux.py)
        Documentation=file:{OPT_DIR}/README.md
        # Wait for the scan$ mount attempts (fstab nofail: the service still starts if a
        # mount fails, and then answers by fail_mode instead of allowing unscanned).
        After=network-online.target remote-fs.target clamav-daemon.socket {mounts}
        Wants=network-online.target clamav-daemon.socket {mounts}

        [Service]
        Type=simple
        User={SVC_USER}
        Group={SVC_USER}
        SupplementaryGroups=clamav
        ExecStart=/usr/bin/python3 {SERVER_DST} --config {CONF}
        Restart=always
        RestartSec=5
        LimitNOFILE=65536
        # hardening: read-only system, writable log directory only
        NoNewPrivileges=yes
        ProtectSystem=strict
        ReadWritePaths={LOG_DIR}
        ProtectHome=yes
        PrivateTmp=yes
        PrivateDevices=yes
        ProtectKernelTunables=yes
        ProtectKernelModules=yes
        ProtectControlGroups=yes
        RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
        RestrictRealtime=yes
        LockPersonality=yes

        [Install]
        WantedBy=multi-user.target
        """)


LOGROTATE_TEXT = f"""# Written by setup_scanner.py
{LOG_DIR}/fpolicy_av.log {LOG_DIR}/fpolicy_av_raw.log {{
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su {SVC_USER} {SVC_USER}
}}
"""


def step_service(ui, plan, facts):
    if not plan["service"]:
        ui.skip(f"not installed; run it by hand: sudo -u {SVC_USER} python3 {SERVER_DST} "
                f"--config {CONF}")
        return "skip"
    ui.write_file(SERVICE_FILE, unit_text(plan))
    ui.write_file(LOGROTATE, LOGROTATE_TEXT)
    ui.run(["systemctl", "daemon-reload"])
    ui.run(["systemctl", "enable", SERVICE])
    ui.run(["systemctl", "restart", SERVICE])
    if ui.dry_run:
        return
    port = int(plan["server"]["port"])
    host = "127.0.0.1" if plan["server"]["bind"] in ("0.0.0.0", "::") else plan["server"]["bind"]
    t0 = time.time()
    while not tcp_check(host, port, 1)[0]:
        if time.time() - t0 > 20:
            ui.run(["journalctl", "-u", SERVICE, "-n", "40", "--no-pager"], check=False,
                   changes=False)
            raise StepError(f"{SERVICE} is not listening on {port} after 20 s")
        time.sleep(1)
    ui.ok(f"listening on {plan['server']['bind']}:{port} after {time.time() - t0:.1f} s")
    ui.run(["ss", "-ltnp", f"sport = :{port}"], check=False, changes=False)
    ui.run(["systemctl", "--no-pager", "-n", "8", "status", SERVICE], check=False, changes=False)


def step_selftest(ui, plan, facts):
    if not plan["service"]:
        ui.skip("service not installed")
        return "skip"
    ui.note("This process plays ONTAP: it opens an FPolicy connection to the scanner, does the "
            "handshake and sends screen requests for a real file, a missing file and an "
            "unconfigured share.")
    r = ui.run(["runuser", "-u", SVC_USER, "--", sys.executable, SERVER_DST, "--config", CONF,
                "--selftest"], check=False, changes=ui.dry_run)
    if not r.ok and not ui.dry_run:
        raise StepError("FPolicy self-test failed")
    if not ui.dry_run:
        ui.say("the scanner logged:")
        ui.run(["tail", "-n", "8", f"{LOG_DIR}/fpolicy_av.log"], check=False, changes=False)
    ui.ok("the scanner answers FPolicy requests")


def step_firewall(ui, plan, facts):
    port = plan["server"]["port"]
    if not facts.get("ufw_active"):
        ui.skip("ufw is not active: nothing to do on the host. Filter TCP "
                f"{port} with the security group (printed in the next step).")
        return "skip"
    if not plan["firewall"]:
        ui.skip("you chose not to add ufw rules")
        return "skip"
    sources = [x for x in plan["server"]["allowed_clients"].split(",") if x]
    if sources:
        for src in sources:
            ui.run(["ufw", "allow", "proto", "tcp", "from", src, "to", "any", "port", str(port),
                    "comment", "fpolicy-av"])
    else:
        ui.run(["ufw", "allow", f"{port}/tcp", "comment", "fpolicy-av"])
    ui.run(["ufw", "status", "numbered"], check=False, changes=False)
    ui.ok("ufw rules added (ufw itself was not enabled or disabled)")


def step_handoff(ui, plan, facts):
    text = ontap_text(plan)
    ui.write_file(ONTAP_TXT, text, 0o644, show="none")
    ui.write_file(ANSWERS, json.dumps(answers_to_save(plan), indent=2) + "\n", 0o600,
                  show="none")
    ui.note(f"Copy {ANSWERS} to the next scanner and run the wizard there with "
            f"--answers to reuse every answer except the passwords.")
    ui.say("ONTAP commands (saved in " + ONTAP_TXT + "):")
    ui.block(text, prefix="    ", limit=400)
    ui.ok("hand-off files written")


def answers_to_save(plan):
    a = json.loads(json.dumps(plan))
    for s in a["svms"]:
        s.pop("password", None)
    a["cache"].pop("password", None)
    a["wizard"], a["version"] = WIZARD, WIZARD_VERSION
    a["saved"] = datetime.datetime.now().isoformat(timespec="seconds")
    return a


STEPS = [
    ("Configure the download proxy", "Only when you gave a proxy: apt (and freshclam) use it.",
     step_proxy),
    ("Refresh the package index", "apt-get update, with timeouts so it can't hang.",
     step_apt_update),
    ("Install packages", "ClamAV daemon and updater, cifs-utils for the mounts, and the "
     "Python Redis client.", step_packages),
    ("Check the kernel SMB client", "mount -t cifs needs the cifs kernel module.", step_cifs),
    ("Create the service account", "A dedicated unprivileged user runs the scanner.",
     step_user),
    ("Configure clamd", "Socket, size limits and the VERSION command in clamd.conf; systemd "
     "and AppArmor adjustments Ubuntu needs.", step_clamd_config),
    ("Install virus signatures", "Official signatures with freshclam and/or the lab EICAR "
     "signature.", step_signatures),
    ("Start clamd and test it", "Start the daemon, wait for the database, and scan an EICAR "
     "and a clean test file both ways (fdpass and INSTREAM).", step_clamd_start),
    ("Store the SMB credentials", "One root-only credentials file per SVM for mount.cifs.",
     step_creds),
    ("Check network access to the SVMs", "DNS and TCP 445 to each SMB endpoint before "
     "mounting.", step_network),
    ("Mount the scan$ shares", "Read-only CIFS mounts, then a listing and a read test as the "
     "service user.", step_mount),
    ("Persist the mounts in /etc/fstab", "A managed block, then a remount from fstab to "
     "prove it works.", step_fstab),
    ("Test the shared verdict cache", "Connect, check the role and do a write/read test.",
     step_cache),
    ("Write the scanner configuration", "/etc/fpolicy-av/scanner.conf from your answers.",
     step_config),
    ("Install the FPolicy server", "Copy fpolicy_av_linux.py to /opt and run its health "
     "check as the service user.", step_install_server),
    ("Start the fpolicy-av service", "systemd unit (hardened), log rotation, start, and "
     "wait until it listens.", step_service),
    ("FPolicy protocol self-test", "Play ONTAP against the running service.", step_selftest),
    ("Host firewall", "Only when ufw is active; it is never switched on or off.",
     step_firewall),
    ("Save the ONTAP commands and answers", "Everything you run on ONTAP, plus your answers "
     "for the next scanner.", step_handoff),
]


def skip_step(fn, plan):
    if fn is step_fstab and not plan["fstab"]:
        return "you chose not to add fstab entries"
    return None


def execute(ui, steps, plan, facts):
    ui.phase(4, 4, "Install" + (" (DRY RUN: nothing is changed)" if ui.dry_run else ""))
    results = []
    n = len(steps)
    for i, (title, why, fn) in enumerate(steps, start=1):
        ui.step_header(i, n, title, why)
        reason = skip_step(fn, plan)
        if reason:
            ui.skip(reason)
            results.append((title, "skip", 0.0))
            continue
        t0 = time.time()
        while True:
            try:
                ret = fn(ui, plan, facts)
                status = "skip" if ret == "skip" and ui.step_status == "ok" else ui.step_status
                results.append((title, status, time.time() - t0))
                break
            except (StepError, OSError, ValueError, RuntimeError) as e:
                ui.fail(str(e) if isinstance(e, StepError) else f"{e.__class__.__name__}: {e}")
                if ui.dry_run:
                    ui.note("dry run: continuing with the next step")
                    results.append((title, "fail", time.time() - t0))
                    break
                if not ui.interactive:
                    results.append((title, "fail", time.time() - t0))
                    finish(ui, results, plan, aborted=True)
                    sys.exit(1)
                choice = ui.ask_choice("Retry, skip this step, or abort", ["r", "s", "a"], "r")
                if choice == "r":
                    ui.step_status = "ok"
                    continue
                if choice == "s":
                    ui.warn("step skipped after a failure")
                    results.append((title, "fail", time.time() - t0))
                    break
                results.append((title, "fail", time.time() - t0))
                finish(ui, results, plan, aborted=True)
                sys.exit(1)
    return results


def finish(ui, results, plan, aborted=False):
    ui.emit("")
    ui.emit(ui.RULE, ui.BOLD)
    ui.emit(" RESULT" + (" (aborted)" if aborted else "") + (" (dry run)" if ui.dry_run else ""),
            ui.BOLD)
    ui.emit(ui.RULE, ui.BOLD)
    colors = {"ok": ui.GREEN, "warn": ui.YELLOW, "fail": ui.RED, "skip": ui.DIM}
    for i, (title, status, dt) in enumerate(results, start=1):
        ui.emit(f"  {i:>2}. [{status.upper():^4}] {title:<44} {dt:6.1f} s", colors.get(status))
    if aborted:
        ui.emit(f"\n  Install log: {ui.log_path}")
        return
    port = plan["server"]["port"]
    ui.emit("")
    ui.say("Files:")
    for path, what in ((CONF, "scanner configuration"), (CRED_DIR, "SMB credentials"),
                       (SERVER_DST, "FPolicy server"), (SERVICE_FILE, "systemd unit"),
                       (ONTAP_TXT, "ONTAP + SG commands"),
                       (ANSWERS, "answers for the next scanner"),
                       (f"{LOG_DIR}/fpolicy_av.log", "decision log"),
                       (ui.log_path, "this install log")):
        ui.kv(what, path)
    ui.emit("")
    ui.say("Next:")
    for ln in (f"1. Security groups: allow TCP {port} to this instance from the SVM data LIFs, "
               "and TCP 445 from this instance to the SVM.",
               f"2. Run the ONTAP commands in {ONTAP_TXT} on the cluster.",
               "3. ONTAP: vserver fpolicy show-engine -vserver <svm>   -> status connected",
               f"4. Watch decisions: sudo tail -f {LOG_DIR}/fpolicy_av.log  "
               f"(or journalctl -u fpolicy-av -f)",
               "5. Test: save the EICAR string to a file on a watched share, close it, open it "
               "again -> Access denied.",
               f"Health check any time: sudo -u {SVC_USER} python3 {SERVER_DST} --check",
               f"Remove everything: sudo python3 {os.path.abspath(__file__)} --uninstall"):
        ui.say("  " + ln)


# ============================================================= UNINSTALL ====
def uninstall(ui):
    ui.banner(f"{WIZARD}.py {WIZARD_VERSION}: UNINSTALL" + (" (dry run)" if ui.dry_run else ""),
              "Removes what this wizard installed. Packages (ClamAV, cifs-utils) are kept.")
    prev = {}
    if os.path.exists(ANSWERS):
        prev = json.loads(read_text(ANSWERS) or "{}")
    mounts = [s["mnt"] for s in prev.get("svms", [])]
    fstab = read_text("/etc/fstab")
    m = re.search(r">>> fpolicy-av scan\$ mounts.*?<<<", fstab, re.DOTALL)
    if m:
        for line in m.group(0).splitlines()[1:-1]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in mounts:
                mounts.append(parts[1])
    ui.section("Plan")
    ui.kv("service", SERVICE_FILE)
    ui.kv("mounts", ", ".join(mounts) or "none found")
    ui.kv("files", f"{OPT_DIR}, {CONF}, {CRED_DIR}, {LOGROTATE}")
    if not ui.ask_yes("Proceed?", not ui.interactive):
        sys.exit("aborted")
    keep_logs = ui.ask_yes(f"Keep the decision logs in {LOG_DIR}?", True)
    revert_clamd = ui.ask_yes("Remove the clamd systemd drop-ins, AppArmor rules and the lab "
                              "EICAR signature?", True)
    remove_user = ui.ask_yes(f"Remove the {SVC_USER} user?", True)

    ui.section("Service")
    ui.run(["systemctl", "disable", "--now", SERVICE], check=False)
    ui.remove_path(SERVICE_FILE)
    ui.remove_path(LOGROTATE)
    ui.run(["systemctl", "daemon-reload"], check=False)
    ui.section("Mounts")
    for mnt in mounts:
        if os.path.ismount(mnt):
            ui.run(["umount", mnt], check=False)
        else:
            ui.say(f"not mounted: {mnt}")
    if m:
        ui.write_file("/etc/fstab", remove_managed_block(fstab, "fpolicy-av scan$ mounts"),
                      0o644, show="diff")
    for mnt in mounts:
        if os.path.isdir(mnt) and not os.path.ismount(mnt) and not os.listdir(mnt):
            ui.remove_path(mnt)
    ui.section("Files")
    ui.remove_path(OPT_DIR)
    for path in (CONF, CRED_DIR, ANSWERS, ONTAP_TXT):
        ui.remove_path(path)
    for path in glob.glob(CONF + ".fpav-backup-*"):
        ui.remove_path(path)
    if os.path.isdir(CONF_DIR) and not os.listdir(CONF_DIR):
        ui.remove_path(CONF_DIR)
    elif os.path.isdir(CONF_DIR):
        ui.note(f"{CONF_DIR} kept: it still holds {', '.join(os.listdir(CONF_DIR))}")
    if not keep_logs:
        ui.remove_path(LOG_DIR)
    if os.path.exists(APT_PROXY_CONF):
        ui.remove_path(APT_PROXY_CONF)
    if revert_clamd:
        ui.section("clamd")
        for d in CLAMD_DROPINS:
            ui.remove_path(d)
        ui.remove_path(LAB_SIG)
        if os.path.exists(APPARMOR_LOCAL):
            cur = read_text(APPARMOR_LOCAL)
            ui.write_file(APPARMOR_LOCAL, remove_managed_block(cur, "fpolicy-av scan$ mounts"),
                          0o644, show="diff")
            if shutil.which("apparmor_parser"):
                ui.run(["apparmor_parser", "-r", APPARMOR_PROFILE], check=False)
        ui.run(["systemctl", "daemon-reload"], check=False)
        ui.note(f"clamd.conf keeps the tuned settings; backups are next to it "
                f"({CLAMD_CONF}.fpav-backup-*).")
    if remove_user:
        ui.section("User")
        ui.run(["userdel", "--remove", SVC_USER], check=False)
    ui.section("Done")
    ui.say("Packages were kept. To remove them too:")
    ui.say("  sudo apt-get purge clamav clamav-daemon clamav-freshclam clamdscan cifs-utils")
    ui.say("On ONTAP, remove the scanner IP from av_engine (or delete the policy), and the scan$ "
           "share if no scanner uses it any more.")


# ================================================================== MAIN ====
def main():
    ap = argparse.ArgumentParser(
        description="Install the Linux FPolicy AV scanner (ClamAV + fpolicy_av_linux.py).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Usage")[1]
        if "Usage" in __doc__ else None)
    ap.add_argument("--dry-run", action="store_true",
                    help="ask the questions and show every step and file, change nothing")
    ap.add_argument("--answers", metavar="FILE",
                    help=f"reuse answers from FILE (default: {ANSWERS} if it exists)")
    ap.add_argument("--non-interactive", action="store_true",
                    help="no prompts: use the answers file; passwords from environment")
    ap.add_argument("--uninstall", action="store_true", help="remove what the wizard installed")
    ap.add_argument("--version", action="version", version=f"{WIZARD}.py {WIZARD_VERSION}")
    args = ap.parse_args()

    if sys.platform != "linux":
        sys.exit("Run this on the Linux scanner host.")
    ui = UI(dry_run=args.dry_run, interactive=not args.non_interactive)
    if os.geteuid() != 0 and not args.dry_run:
        sys.exit("Run as root:  sudo python3 " + " ".join(sys.argv))
    ui.open_log(SETUP_LOG_DIR, WIZARD)

    if args.uninstall:
        uninstall(ui)
        return

    ui.banner(f"Linux FPolicy AV scanner - {WIZARD}.py {WIZARD_VERSION}"
              + ("   [DRY RUN]" if args.dry_run else ""),
              "ClamAV + read-only scan$ mounts + fpolicy_av_linux.py as the fpolicy-av service.\n"
              f"Install log: {ui.log_path}\n"
              "Lab tool, not a NetApp-supported antivirus integration.")
    answers_path = args.answers or (ANSWERS if os.path.exists(ANSWERS) else None)
    prev = {}
    if answers_path:
        try:
            prev = json.loads(read_text(answers_path) or "{}")
            ui.note(f"answers loaded from {answers_path} (saved {prev.get('saved', '?')})")
        except ValueError as e:
            sys.exit(f"{answers_path}: not valid JSON ({e})")
    elif args.non_interactive:
        sys.exit("--non-interactive needs --answers FILE")

    facts = preflight(ui, args)
    plan = collect(ui, facts, prev)
    summary(ui, plan, facts)
    steps = STEPS
    ui.emit("")
    if not ui.ask_yes(f"Run the {len(steps)} install steps"
                      + (" in dry-run mode" if ui.dry_run else "") + " now?", True):
        sys.exit("aborted: nothing was changed")
    results = execute(ui, steps, plan, facts)
    finish(ui, results, plan)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
