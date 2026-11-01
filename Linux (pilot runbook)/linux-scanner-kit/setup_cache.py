#!/usr/bin/env python3
"""Cache wizard for the Linux FPolicy AV scanners (version 2).

Installs the shared verdict cache (Redis or Valkey) on an Ubuntu 22.04 / 24.04
host (an EC2 instance, for example), in one of three roles:

  primary    takes the writes from every scanner
  replica    keeps a live copy of the primary (replicaof), read-only
  sentinel   Sentinel only, no data (e.g. the third Sentinel on a scanner host)

Primary and replica can also run Sentinel, for automatic failover (you need
at least three Sentinels in total).

It runs in four phases and prints everything it does:
  1. preflight checks                     - changes nothing
  2. questions                            - changes nothing
  3. summary and confirmation             - changes nothing
  4. numbered install steps: every command with its output, exit code and
     time, every config change (passwords masked), and checks at the end

Usage:
  sudo python3 setup_cache.py                  interactive install
  sudo python3 setup_cache.py --dry-run        show every step, change nothing
  sudo python3 setup_cache.py --answers FILE   reuse answers
  sudo python3 setup_cache.py --answers FILE --non-interactive
                                               unattended (FPAV_CACHE_PASSWORD)
  sudo python3 setup_cache.py --uninstall      remove the wizard's configuration

Engines: Valkey is packaged on Ubuntu 24.04 (noble-updates). On 22.04 Valkey is
built from source (needs GitHub and build tools); Redis is packaged on both.

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

WIZARD = "setup_cache"
WIZARD_VERSION = "2.0"
STATE_DIR = "/etc/fpolicy-av"
ANSWERS = os.path.join(STATE_DIR, "cache-wizard-answers.json")
SETUP_LOG_DIR = "/var/log/fpolicy-av-setup"
APT_PROXY_CONF = "/etc/apt/apt.conf.d/95fpolicy-av-proxy"
VALKEY_FALLBACK_VERSION = "9.1.3"
BLOCK = "fpolicy-av verdict cache"
SENTINEL_BLOCK = "fpolicy-av sentinel"

LAYOUT = {
    "redis": {"server_pkg": ["redis-server", "redis-tools"],
              "sentinel_pkg": ["redis-sentinel", "redis-tools"],
              "service": "redis-server", "conf": "/etc/redis/redis.conf",
              "sentinel_service": "redis-sentinel", "sentinel_conf": "/etc/redis/sentinel.conf",
              "cli": "redis-cli", "user": "redis", "dir": "/var/lib/redis", "source": False},
    "valkey": {"server_pkg": ["valkey-server", "valkey-tools"],
               "sentinel_pkg": ["valkey-sentinel", "valkey-tools"],
               "service": "valkey-server", "conf": "/etc/valkey/valkey.conf",
               "sentinel_service": "valkey-sentinel", "sentinel_conf": "/etc/valkey/sentinel.conf",
               "cli": "valkey-cli", "user": "valkey", "dir": "/var/lib/valkey", "source": False},
}
SOURCE_LAYOUT = dict(LAYOUT["valkey"], source=True, cli="/usr/local/bin/valkey-cli",
                     server_bin="/usr/local/bin/valkey-server",
                     sentinel_bin="/usr/local/bin/valkey-sentinel")
BUILD_DEPS = ["build-essential", "pkg-config", "libssl-dev", "curl", "ca-certificates"]

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


# ------------------------------------------------------------- helpers ------
def v_proxy(x):
    if re.fullmatch(r"https?://[^\s/:]+:\d+/?", x.strip()):
        return True, x.strip().rstrip("/")
    return False, "use http://host:port"


def v_ip(x):
    try:
        return True, str(ipaddress.ip_address(x.strip()))
    except ValueError:
        return False, "enter an IP address (not a DNS name)"


def v_mem(x):
    x = x.strip().lower()
    return (True, x) if re.fullmatch(r"\d+(mb|gb)", x) else (False, "use e.g. 512mb or 2gb")


def apt_candidate(pkg):
    """Candidate version from apt-cache, '' if none/unknown."""
    try:
        out = subprocess.run(["apt-cache", "policy", pkg], capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(r"Candidate:\s*(\S+)", out)
    return "" if not m or m.group(1) == "(none)" else m.group(1)


def cli_env(password):
    # redis-cli / valkey-cli read the password from the environment, so it
    # never appears on a command line or in this wizard's output.
    return {"REDISCLI_AUTH": password, "VALKEYCLI_AUTH": password} if password else {}


def layout_for(plan):
    if plan["engine"] == "valkey" and plan.get("valkey_source"):
        return dict(SOURCE_LAYOUT)
    return dict(LAYOUT[plan["engine"]])


def server_block_lines(plan, lay):
    lines = [f"bind 127.0.0.1 {plan['ip']}" if plan["ip"] not in ("127.0.0.1", "")
             else "bind 127.0.0.1",
             # Redis 7 / Valkey refuse remote clients without a password while
             # protected-mode is on, whatever 'bind' says
             "protected-mode yes" if plan["password"] else "protected-mode no",
             f"port {plan['port']}",
             f"maxmemory {plan['maxmemory']}",
             "maxmemory-policy allkeys-lru"]
    if plan["password"]:
        # the same password on every node: requirepass for clients, masterauth so
        # any node can replicate from any other after a failover
        lines += [f"requirepass {plan['password']}", f"masterauth {plan['password']}"]
    # 'save ""' clears the package defaults first; one pair per line works on
    # Redis 6 (Ubuntu 22.04) and Redis 7 / Valkey.
    p = plan["persistence"]
    lines += ['save ""']
    if p in ("rdb", "both"):
        lines += ["save 3600 1", "save 300 100", "save 60 10000"]
    lines += ["appendonly yes", "appendfsync everysec"] if p in ("aof", "both") \
        else ["appendonly no"]
    if plan["role"] == "replica":
        lines += [f"replicaof {plan['primary_host']} {plan['primary_port']}",
                  "replica-read-only yes"]
    if lay.get("source"):
        lines += [f"dir {lay['dir']}", "daemonize no", "supervised no", 'logfile ""']
    return lines


def sentinel_block_lines(plan, lay):
    s = plan["sentinel"]
    name = s["name"]
    lines = [f"bind 127.0.0.1 {plan['ip']}" if plan["ip"] not in ("127.0.0.1", "")
             else "bind 127.0.0.1",
             f"port {s['port']}",
             f"sentinel monitor {name} {s['monitor_host']} {s['monitor_port']} {s['quorum']}",
             f"sentinel down-after-milliseconds {name} {s['down_after_ms']}",
             f"sentinel failover-timeout {name} {s['failover_timeout_ms']}",
             f"sentinel parallel-syncs {name} 1"]
    if plan["password"]:
        lines += [f"sentinel auth-pass {name} {plan['password']}",
                  f"requirepass {plan['password']}"]
    if lay.get("source"):
        lines += [f"dir {lay['dir']}", "daemonize no"]
    return lines


def disable_default_master(text):
    """Comment out the package's 'mymaster' example monitor (it points at 127.0.0.1)."""
    out = []
    for line in text.splitlines():
        if re.match(r"\s*sentinel\s+\S+\s+mymaster\b", line, re.I) or \
                re.match(r"\s*sentinel\s+monitor\s+mymaster\b", line, re.I):
            out.append("# fpav-disabled: " + line)
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") or text else "")


def restore_default_master(text):
    return re.sub(r"(?m)^# fpav-disabled: ", "", text)


def mem_default(mem_mb):
    return f"{max(256, min(mem_mb // 4, 8192)) // 256 * 256}mb" if mem_mb else "1gb"


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
    name = osr.get("PRETTY_NAME", "unknown")
    if osr.get("ID") == "ubuntu" and osr.get("VERSION_ID") in ("22.04", "24.04"):
        row("OK", "operating system", name)
    elif shutil.which("apt-get"):
        row("WARN", "operating system", f"{name} (tested on Ubuntu 22.04 and 24.04 only)")
    else:
        row("FAIL", "operating system", f"{name}: needs Ubuntu (apt)")
    row("OK" if sys.version_info >= (3, 8) else "FAIL", "python", sys.version.split()[0])
    row("OK" if systemd_running() else ("WARN" if args.dry_run else "FAIL"), "systemd",
        "running" if systemd_running() else "not PID 1")
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
    mem = meminfo_mb()
    facts["mem_mb"] = mem
    row("OK" if mem >= 1800 else "WARN", "CPU / memory",
        f"{os.cpu_count()} vCPU, {mem} MB RAM (verdicts are ~200 bytes each: 1 GB holds "
        f"about 5 million)")
    row("OK" if disk_free_mb("/var/lib") >= 1024 else "WARN", "free disk in /var/lib",
        f"{disk_free_mb('/var/lib')} MB")
    for scheme, host in apt_mirror_hosts()[:2]:
        ok, ms, err = tcp_check(host, 443 if scheme == "https" else 80, 5)
        row("OK" if ok else "WARN", "package mirror", f"{host} {'reachable' if ok else err}")
    ok, ms, err = tcp_check("github.com", 443, 5)
    facts["github_ok"] = ok
    row("OK" if ok else "INFO", "github.com (Valkey source)",
        "reachable" if ok else f"{err} (only needed to build Valkey on 22.04)")
    facts["valkey_pkg"] = apt_candidate("valkey-server")
    facts["redis_pkg"] = apt_candidate("redis-server")
    row("INFO", "packaged engines", f"valkey-server {facts['valkey_pkg'] or 'not in apt (yet)'}, "
                                    f"redis-server {facts['redis_pkg'] or 'not in apt (yet)'}")
    if not facts["valkey_pkg"] and not facts["redis_pkg"]:
        ui.note("apt has no package lists yet (fresh image?): availability is checked again "
                "after apt-get update.")
    rc, out = ui.probe(["ufw", "status"])
    facts["ufw_active"] = "Status: active" in out
    row("INFO", "host firewall (ufw)", "active" if facts["ufw_active"] else
        "inactive or not installed (normal on EC2: security groups filter traffic)")
    running = []
    for svc in ("redis-server", "valkey-server", "redis-sentinel", "valkey-sentinel"):
        rc, out = ui.probe(["systemctl", "is-active", svc])
        if out.strip() == "active":
            running.append(svc)
    facts["running"] = running
    row("INFO", "running cache services", ", ".join(running) or "none")
    if facts["fail"] and not args.dry_run:
        ui.fail("preflight found blocking problems (FAIL above). Fix them and re-run.")
        sys.exit(2)
    return facts


# ============================================================== PHASE 2 =====
def current_master(lay, port, name, password):
    """Primary that a running Sentinel on this host knows about, or None."""
    cli = lay["cli"] if shutil.which(lay["cli"]) or os.path.exists(lay["cli"]) else None
    if not cli:
        return None
    try:
        out = subprocess.run([cli, "-p", str(port), "--no-auth-warning", "sentinel",
                              "get-master-addr-by-name", name], capture_output=True, text=True,
                             timeout=5, env=dict(os.environ, **cli_env(password))).stdout.split()
        return (out[0], out[1]) if len(out) >= 2 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def collect(ui, facts, prev):
    ui.phase(2, 4, "Questions (nothing is changed yet)")
    ui.note("Press Enter to accept the value in [brackets].")
    plan = {}
    ui.section("Software")
    plan["proxy"] = ui.ask("HTTP proxy for downloads (blank = none)", prev.get("proxy", ""),
                           v_proxy, allow_empty=True,
                           help="Only if this host reaches the internet through a proxy.")
    jammy = facts["os"].get("VERSION_ID") == "22.04"
    default_engine = prev.get("engine") or ("redis" if jammy and not facts["valkey_pkg"]
                                            else "valkey")
    plan["engine"] = ui.ask_choice(
        "Cache engine", ["valkey", "redis"], default_engine,
        help="Valkey (BSD licence, Linux Foundation fork of Redis) and Redis behave the same "
             "for the scanner. Ubuntu 24.04 packages Valkey; 22.04 only packages Redis, so "
             "Valkey there is built from source (a few minutes, needs GitHub).")
    plan["valkey_source"] = False
    if plan["engine"] == "valkey" and not facts["valkey_pkg"] and jammy:
        plan["valkey_source"] = ui.ask_yes(
            "No Valkey package on this release: build Valkey from source?",
            prev.get("valkey_source", True),
            help="Installs build-essential, pkg-config and libssl-dev, downloads the release "
                 "from GitHub, builds it with TLS support and installs it in /usr/local with "
                 "its own systemd units. Answer no to stop and pick Redis instead.")
        if not plan["valkey_source"]:
            raise SystemExit("choose redis as the engine, or allow the source build")
        if plan["valkey_source"]:
            plan["valkey_version"] = ui.ask("Valkey version to build",
                                            prev.get("valkey_version") or latest_valkey(),
                                            lambda x: (True, x.strip().lstrip("vV"))
                                            if re.fullmatch(r"[vV]?\d+\.\d+\.\d+", x.strip())
                                            else (False, "use a release number like 8.1.4"),
                                            help="Defaults to the latest GitHub release.")
    lay = layout_for(plan)

    ui.section("Role")
    plan["role"] = ui.ask_choice(
        "Role of this host", ["primary", "replica", "sentinel"], prev.get("role", "primary"),
        help="primary = the scanners write here; replica = a live read-only copy that Sentinel "
             "can promote; sentinel = only a Sentinel process (e.g. the third one, on a "
             "scanner host).")
    plan["ip"] = ui.ask("This host's IP address (to listen on)",
                        facts.get("ip") or prev.get("ip"), v_ip,
                        help="The private IP the scanners and the other cache nodes use. "
                             "127.0.0.1 is always added.")
    plan["password"] = ui.ask_secret(
        "Cache password (the same on every cache node and in setup_scanner.py)",
        ("FPAV_CACHE_PASSWORD",), allow_empty=True)
    if not plan["password"]:
        ui.warn("no password: anyone who can reach the port can read and change verdicts")

    if plan["role"] != "sentinel":
        ui.section("Data node")
        plan["port"] = ui.ask("Port", prev.get("port", 6379), v_port)
        plan["maxmemory"] = ui.ask("Memory limit for verdicts", prev.get("maxmemory")
                                   or mem_default(facts.get("mem_mb", 0)), v_mem,
                                   help="When full, the least recently used verdicts are "
                                        "evicted (allkeys-lru): a lost verdict only costs one "
                                        "rescan.")
        plan["persistence"] = ui.ask_choice(
            "Persistence", ["none", "rdb", "aof", "both"], prev.get("persistence", "rdb"),
            help="rdb = periodic snapshot (verdicts survive a restart); aof = append log; "
                 "none = memory only (the scanners rebuild the cache by scanning).")
        if plan["role"] == "replica":
            plan["primary_host"] = ui.ask("Primary host/IP to replicate from",
                                          prev.get("primary_host"), v_host)
            plan["primary_port"] = ui.ask("Primary port", prev.get("primary_port", 6379), v_port)
        want_sentinel = ui.ask_yes(
            "Also run Sentinel on this host (automatic failover)?",
            prev.get("sentinel") is not None if prev else False,
            help="Sentinels watch the primary and promote a replica if it fails. You need "
                 "three in total, e.g. on both cache nodes and on one scanner.")
    else:
        want_sentinel = True
    plan["sentinel"] = None
    if want_sentinel:
        ui.section("Sentinel")
        ps = prev.get("sentinel") or {}
        s = {}
        s["name"] = ui.ask("Monitored primary name", ps.get("name", "fpolicy-cache"),
                           help="The scanners use this name to ask Sentinel for the primary.")
        s["port"] = ui.ask("Sentinel port", ps.get("port", 26379), v_port)
        known = current_master(lay, s["port"], s["name"], plan["password"])
        if known:
            ui.note(f"the Sentinel running here reports the current primary as {known[0]}:"
                    f"{known[1]} (after a failover this differs from the original primary)")
        if plan["role"] == "primary":
            d_host, d_port = known or (plan["ip"], plan["port"])
        elif plan["role"] == "replica":
            d_host, d_port = known or (plan["primary_host"], plan["primary_port"])
        else:
            d_host, d_port = known or (ps.get("monitor_host"), ps.get("monitor_port", 6379))
        s["monitor_host"] = ui.ask("Primary to monitor: IP address", d_host, v_ip,
                                   help="An IP address: Sentinel on Redis 6 can't use names.")
        s["monitor_port"] = ui.ask("Primary to monitor: port", d_port, v_port)
        s["quorum"] = ui.ask_int("Quorum (Sentinels that must agree the primary is down)",
                                 ps.get("quorum", 2), 1, 9)
        s["down_after_ms"] = ui.ask_int("Declare the primary down after (ms)",
                                        ps.get("down_after_ms", 5000), 1000, 600000)
        s["failover_timeout_ms"] = ui.ask_int("Failover timeout (ms)",
                                              ps.get("failover_timeout_ms", 60000), 5000, 3600000)
        plan["sentinel"] = s

    plan["firewall_sources"] = ""
    if facts.get("ufw_active"):
        plan["firewall_sources"] = ui.ask(
            "ufw is active: allow the cache ports from (IPs/CIDRs: scanners and the other "
            "cache nodes)", prev.get("firewall_sources", ""), v_ip_list, allow_empty=True)
    return plan


def latest_valkey():
    """Latest release tag: GitHub API, then the releases/latest redirect, then a constant."""
    try:
        with urllib.request.urlopen("https://api.github.com/repos/valkey-io/valkey/releases/latest",
                                    timeout=10) as r:
            return json.load(r)["tag_name"].lstrip("v")
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://github.com/valkey-io/valkey/releases/latest",
                                    timeout=10) as r:
            m = re.search(r"/releases/tag/v?([0-9][0-9.]*)$", r.geturl())
            if m:
                return m.group(1)
    except Exception:
        pass
    return VALKEY_FALLBACK_VERSION


# ============================================================== PHASE 3 =====
def summary(ui, plan, facts):
    ui.phase(3, 4, "Summary (nothing is changed yet)")
    lay = layout_for(plan)
    ui.section("What will be configured")
    ui.kv("engine", plan["engine"] + (f" {plan.get('valkey_version')} (built from source)"
                                      if plan.get("valkey_source") else " (Ubuntu package)"))
    ui.kv("role", plan["role"])
    ui.kv("listen IP", f"127.0.0.1 + {plan['ip']}")
    ui.kv("password", "set" if plan["password"] else "NONE")
    if plan["role"] != "sentinel":
        ui.kv("data node", f"port {plan['port']}, maxmemory {plan['maxmemory']} "
                           f"(allkeys-lru), persistence {plan['persistence']}")
        ui.kv("config file", lay["conf"])
        if plan["role"] == "replica":
            ui.kv("replicates from", f"{plan['primary_host']}:{plan['primary_port']}")
    s = plan["sentinel"]
    if s:
        ui.kv("sentinel", f"port {s['port']}, monitors {s['name']} at {s['monitor_host']}:"
                          f"{s['monitor_port']}, quorum {s['quorum']}, down after "
                          f"{s['down_after_ms']} ms")
        ui.kv("sentinel config file", lay["sentinel_conf"])
    ui.kv("ufw", plan["firewall_sources"] or ("active, no rules" if facts.get("ufw_active")
                                              else "inactive: use security groups"))


# ============================================================== PHASE 4 =====
# Timeouts so a host without internet fails fast; wait up to 10 min for the dpkg lock
# (unattended-upgrades often holds it right after boot); keep edited config files
# on package upgrades instead of prompting.
APT_OPTS = ["-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30",
            "-o", "Acquire::Retries=2", "-o", "Dpkg::Use-Pty=0",
            "-o", "DPkg::Lock::Timeout=600",
            "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


def step_proxy(ui, plan, facts):
    if not plan["proxy"]:
        ui.skip("no proxy configured")
        return "skip"
    ui.write_file(APT_PROXY_CONF, f'Acquire::http::Proxy "{plan["proxy"]}";\n'
                                  f'Acquire::https::Proxy "{plan["proxy"]}";\n')
    os.environ["http_proxy"] = os.environ["https_proxy"] = plan["proxy"]
    ui.ok("apt and the downloads will use the proxy")


def step_apt_update(ui, plan, facts):
    ui.note("Timeouts are set so a host without internet access fails in about a minute "
            "instead of hanging.")
    ui.run(["apt-get"] + APT_OPTS + ["update"], env=APT_ENV, timeout=600)
    ui.ok("package index refreshed")


def packages_for(plan):
    lay = LAYOUT[plan["engine"]]
    pkgs = []
    if plan["role"] != "sentinel":
        pkgs += lay["server_pkg"]
    if plan["sentinel"]:
        pkgs += [p for p in lay["sentinel_pkg"] if p not in pkgs]
    return pkgs


def step_install(ui, plan, facts):
    if plan.get("valkey_source"):
        return build_valkey(ui, plan)
    pkgs = packages_for(plan)
    for p in pkgs:
        cand = apt_candidate(p) if not ui.dry_run else ""
        ui.kv(p, cand or "(candidate checked by apt)")
    ui.run(["apt-get"] + APT_OPTS + ["install", "-y"] + pkgs, env=APT_ENV, timeout=1200)
    rc, out = ui.probe(["dpkg-query", "-W", "-f", "${Package} ${Version}\n"] + pkgs)
    ui.say("package versions now installed:")
    ui.block(out)
    ui.note("The packages start their services with the stock configuration (listening on "
            "127.0.0.1 only); the next steps reconfigure and restart them.")
    ui.ok("packages installed")


def build_valkey(ui, plan):
    ver = plan["valkey_version"]
    lay = dict(SOURCE_LAYOUT)
    ui.say(f"building Valkey {ver} from source (no Ubuntu package on this release)")
    ui.run(["apt-get"] + APT_OPTS + ["install", "-y"] + BUILD_DEPS, env=APT_ENV, timeout=1200)
    src = f"/usr/local/src/valkey-{ver}"
    if not os.path.isfile(os.path.join(src, "Makefile")):
        url = f"https://github.com/valkey-io/valkey/archive/refs/tags/{ver}.tar.gz"
        ui.mkdir("/usr/local/src", 0o755)
        tgz = f"/usr/local/src/valkey-{ver}.tar.gz"
        work = f"/usr/local/src/.valkey-{ver}.unpack"
        # download and unpack into a scratch directory first, so an interrupted
        # download never leaves a half source tree behind
        ui.run(["curl", "-fSL", "--retry", "2", "--max-time", "300", "-o", tgz, url], timeout=360)
        ui.run(["rm", "-rf", work, src])
        ui.run(["mkdir", "-p", work])
        ui.run(["tar", "-xzf", tgz, "-C", work])
        ui.run(["mv", f"{work}/valkey-{ver}", src])
        ui.run(["rm", "-rf", work, tgz])
    else:
        ui.say(f"source tree already present: {src}")
    jobs = str(os.cpu_count() or 2)
    ui.run(["make", "-C", src, "-j", jobs, "BUILD_TLS=yes"], timeout=3600)
    ui.run(["make", "-C", src, "install", "PREFIX=/usr/local"], timeout=600)
    rc, _ = ui.probe(["id", "valkey"])
    if rc != 0:
        ui.run(["useradd", "--system", "--home-dir", "/var/lib/valkey", "--shell",
                "/usr/sbin/nologin", "--comment", "Valkey", "valkey"])
    for d, mode in (("/etc/valkey", 0o750), ("/var/lib/valkey", 0o750), ("/var/log/valkey", 0o750)):
        ui.mkdir(d, mode, ("valkey", "valkey") if not ui.dry_run else None)
    if not os.path.exists(lay["conf"]):
        ui.say(f"base configuration: {src}/valkey.conf -> {lay['conf']}")
        if not ui.dry_run:
            shutil.copy(os.path.join(src, "valkey.conf"), lay["conf"])
            shutil.chown(lay["conf"], "valkey", "valkey")
            os.chmod(lay["conf"], 0o640)
    if plan["sentinel"] and not os.path.exists(lay["sentinel_conf"]):
        ui.write_file(lay["sentinel_conf"], "# Valkey Sentinel (built from source)\n", 0o640,
                      ("valkey", "valkey") if not ui.dry_run else None)
    for name, exe, conf, desc in (("valkey-server", lay["server_bin"], lay["conf"], "Valkey"),
                                  ("valkey-sentinel", lay["sentinel_bin"], lay["sentinel_conf"],
                                   "Valkey Sentinel")):
        ui.write_file(f"/etc/systemd/system/{name}.service", textwrap.dedent(f"""\
            # Written by setup_cache.py {WIZARD_VERSION} (Valkey built from source)
            [Unit]
            Description={desc}
            After=network-online.target
            Wants=network-online.target

            [Service]
            Type=simple
            User=valkey
            Group=valkey
            ExecStart={exe} {conf} --daemonize no
            Restart=always
            LimitNOFILE=65535
            NoNewPrivileges=yes
            ProtectSystem=full
            ReadWritePaths=/var/lib/valkey /var/log/valkey /etc/valkey

            [Install]
            WantedBy=multi-user.target
            """))
    ui.run(["systemctl", "daemon-reload"])
    ui.run([lay["server_bin"], "--version"], check=False, changes=ui.dry_run)
    ui.ok(f"Valkey {ver} built and installed in /usr/local/bin")


def wait_ping(ui, lay, port, password, timeout=60):
    t0 = time.time()
    while True:
        try:
            r = subprocess.run([lay["cli"], "-h", "127.0.0.1", "-p", str(port),
                                "--no-auth-warning", "ping"], capture_output=True, text=True,
                               timeout=5, env=dict(os.environ, **cli_env(password)))
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess([], 1, "", "timeout")
        if "PONG" in r.stdout:
            ui.ok(f"PING -> PONG on port {port} after {time.time() - t0:.1f} s")
            return True
        if time.time() - t0 > timeout:
            ui.fail(f"no PONG on port {port}: {(r.stdout + r.stderr).strip()}")
            return False
        time.sleep(1)


def step_configure_server(ui, plan, facts):
    if plan["role"] == "sentinel":
        ui.skip("sentinel-only host: no data node")
        return "skip"
    lay = layout_for(plan)
    conf = lay["conf"]
    cur = read_text(conf)
    if not cur and not ui.dry_run:
        raise StepError(f"{conf} not found: was the package installed?")
    ui.say(f"{conf}: the managed block goes at the end (later directives win, so the "
           f"package defaults above it stay untouched)")
    lines = server_block_lines(plan, lay)
    explain = {"bind": "listen on localhost and this host's IP only",
               "protected-mode": "refuse remote clients unless a password is set",
               "maxmemory": "memory cap for verdicts",
               "maxmemory-policy": "evict least recently used verdicts when full",
               "requirepass": "password for clients (scanners)",
               "masterauth": "password used when this node replicates",
               "save": "RDB snapshot schedule ('' clears the package defaults)",
               "appendonly": "append-only log", "replicaof": "replicate from the primary",
               "replica-read-only": "replicas refuse writes", "dir": "data directory",
               "port": "TCP port for clients and replication",
               "appendfsync": "fsync the append log every second",
               "daemonize": "systemd runs it in the foreground",
               "supervised": "plain foreground process", "logfile": "log to the journal"}
    for ln in lines:
        key = ln.split()[0]
        ui.kv(f"{key} ********" if key in ("requirepass", "masterauth") else ln,
              explain.get(key, ""))
    new = managed_block(cur, BLOCK, lines)
    ui.write_file(conf, new, 0o640, (lay["user"], lay["user"]) if not ui.dry_run else None,
                  show="none")
    ui.run(["systemctl", "enable", lay["service"]])
    ui.run(["systemctl", "restart", lay["service"]])
    if ui.dry_run:
        return
    if not wait_ping(ui, lay, plan["port"], plan["password"]):
        ui.run(["journalctl", "-u", lay["service"], "-n", "30", "--no-pager"], check=False,
               changes=False)
        raise StepError(f"{lay['service']} does not answer after the restart")
    env = cli_env(plan["password"])
    base = [lay["cli"], "-h", "127.0.0.1", "-p", str(plan["port"]), "--no-auth-warning"]
    ui.run(base + ["config", "get", "bind"], env=env, changes=False, check=False)
    ui.run(base + ["config", "get", "save"], env=env, changes=False, check=False)
    ui.run(base + ["config", "get", "maxmemory"], env=env, changes=False, check=False)
    if plan["role"] == "replica":
        ui.say("waiting for the replication link to come up ...")
        t0 = time.time()
        while time.time() - t0 < 60:
            try:
                r = subprocess.run(base + ["info", "replication"], capture_output=True,
                                   text=True, timeout=5, env=dict(os.environ, **env))
                if "master_link_status:up" in r.stdout:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(2)
        r = ui.run(base + ["info", "replication"], env=env, changes=False, check=False)
        if "master_link_status:up" in r.out:
            ui.ok("replicating from the primary (master_link_status:up)")
        else:
            ui.warn("replication link not up yet: check the primary's address and password, "
                    "and that TCP {} is open from this host to the primary".format(
                        plan["primary_port"]))
    else:
        ui.run(base + ["info", "replication"], env=env, changes=False, check=False)
        ui.run(base + ["set", "verdict:__fpav_setup_test__", "0:", "EX", "60"], env=env,
               changes=False, check=False)
        r = ui.run(base + ["get", "verdict:__fpav_setup_test__"], env=env, changes=False,
                   check=False)
        if r.out.strip() == "0:":
            ui.ok("write/read test passed")
        else:
            ui.warn("write/read test failed")
    ui.ok(f"{lay['service']} configured and running")


def step_configure_sentinel(ui, plan, facts):
    if not plan["sentinel"]:
        ui.skip("no Sentinel on this host")
        return "skip"
    lay = layout_for(plan)
    s = plan["sentinel"]
    conf = lay["sentinel_conf"]
    cur = read_text(conf)
    ui.note("Sentinel rewrites its own config file while running (it appends its id and the "
            "replicas and Sentinels it discovers). The wizard only owns the marked block.")
    cur2 = disable_default_master(cur)
    if cur2 != cur:
        ui.say("commenting out the package's example monitor 'mymaster' (127.0.0.1:6379)")
    lines = sentinel_block_lines(plan, lay)
    for ln in lines:
        ui.kv(ln if "pass" not in ln else " ".join(ln.split()[:-1]) + " ********", "")
    ui.write_file(conf, managed_block(cur2, SENTINEL_BLOCK, lines), 0o640,
                  (lay["user"], lay["user"]) if not ui.dry_run else None, show="none")
    ui.run(["systemctl", "enable", lay["sentinel_service"]])
    ui.run(["systemctl", "restart", lay["sentinel_service"]])
    if ui.dry_run:
        return
    if not wait_ping(ui, lay, s["port"], plan["password"], timeout=30):
        ui.run(["journalctl", "-u", lay["sentinel_service"], "-n", "30", "--no-pager"],
               check=False, changes=False)
        raise StepError("Sentinel does not answer")
    env = cli_env(plan["password"])
    base = [lay["cli"], "-h", "127.0.0.1", "-p", str(s["port"]), "--no-auth-warning"]
    time.sleep(2)
    ui.run(base + ["sentinel", "get-master-addr-by-name", s["name"]], env=env, changes=False,
           check=False)
    r = ui.run(base + ["sentinel", "ckquorum", s["name"]], env=env, changes=False, check=False)
    if "OK" in r.out:
        ui.ok("quorum reachable")
    else:
        ui.warn("quorum not reachable yet: normal until the other Sentinels are installed "
                "(TCP 26379 must be open between them)")
    ui.ok(f"{lay['sentinel_service']} configured and running")


def step_firewall(ui, plan, facts):
    if not facts.get("ufw_active"):
        ui.skip("ufw is not active: use security groups (printed below)")
        return "skip"
    ports = []
    if plan["role"] != "sentinel":
        ports.append(plan["port"])
    if plan["sentinel"]:
        ports.append(plan["sentinel"]["port"])
    srcs = [x for x in plan["firewall_sources"].split(",") if x]
    if not srcs:
        ui.skip("no source addresses given: no rules added")
        return "skip"
    for src in srcs:
        for p in ports:
            ui.run(["ufw", "allow", "proto", "tcp", "from", src, "to", "any", "port", str(p),
                    "comment", "fpolicy-av cache"])
    ui.run(["ufw", "status", "numbered"], check=False, changes=False)
    ui.ok("ufw rules added (ufw itself was not enabled or disabled)")


def step_handoff(ui, plan, facts):
    a = json.loads(json.dumps(plan))
    a.pop("password", None)
    a["wizard"], a["version"] = WIZARD, WIZARD_VERSION
    a["saved"] = datetime.datetime.now().isoformat(timespec="seconds")
    ui.mkdir(STATE_DIR, 0o755, enforce=False)
    ui.write_file(ANSWERS, json.dumps(a, indent=2) + "\n", 0o600, show="none")
    ui.say("Give these to setup_scanner.py on every scanner:")
    ui.kv("cache engine", plan["engine"])
    if plan["sentinel"]:
        ui.kv("connect", "through Sentinel")
        ui.kv("Sentinel servers", f"{plan['ip']}:{plan['sentinel']['port']},"
                                  f"<sentinel-2>:{plan['sentinel']['port']},"
                                  f"<sentinel-3>:{plan['sentinel']['port']}")
        ui.kv("primary name", plan["sentinel"]["name"])
    if plan["role"] != "sentinel":
        ui.kv("or directly", f"{plan['ip']}:{plan['port']}" +
              ("  (the primary)" if plan["role"] == "primary" else "  (a replica: read-only)"))
    ui.kv("password", "the one you entered" if plan["password"] else "none")
    ui.say("AWS security group for the cache nodes:")
    ports = "6379" + (" and 26379" if plan["sentinel"] else "")
    ui.say(f"  inbound TCP {ports} from the scanner SG and from the cache SG itself "
           f"(replication and Sentinel traffic between cache nodes)")
    ui.ok("done")


STEPS = [
    ("Configure the download proxy", "Only when you gave a proxy.", step_proxy),
    ("Refresh the package index", "apt-get update, with timeouts so it can't hang.",
     step_apt_update),
    ("Install the cache engine", "Ubuntu packages, or a Valkey source build on 22.04.",
     step_install),
    ("Configure the data node", "Managed block in the engine's config file, restart, and "
     "checks (PING, bind, save, replication, write/read).", step_configure_server),
    ("Configure Sentinel", "Managed block in sentinel.conf, restart, and quorum check.",
     step_configure_sentinel),
    ("Host firewall", "Only when ufw is active; it is never switched on or off.",
     step_firewall),
    ("Hand-off", "Values for setup_scanner.py, security-group rules, saved answers.",
     step_handoff),
]


def execute(ui, plan, facts):
    ui.phase(4, 4, "Install" + (" (DRY RUN: nothing is changed)" if ui.dry_run else ""))
    results = []
    for i, (title, why, fn) in enumerate(STEPS, start=1):
        ui.step_header(i, len(STEPS), title, why)
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
                    results.append((title, "fail", time.time() - t0))
                    break
                if not ui.interactive:
                    results.append((title, "fail", time.time() - t0))
                    report(ui, results, aborted=True)
                    sys.exit(1)
                choice = ui.ask_choice("Retry, skip this step, or abort", ["r", "s", "a"], "r")
                if choice == "r":
                    ui.step_status = "ok"
                    continue
                results.append((title, "fail", time.time() - t0))
                if choice == "s":
                    break
                report(ui, results, aborted=True)
                sys.exit(1)
    report(ui, results)


def report(ui, results, aborted=False):
    ui.emit("")
    ui.emit(ui.RULE, ui.BOLD)
    ui.emit(" RESULT" + (" (aborted)" if aborted else "") + (" (dry run)" if ui.dry_run else ""),
            ui.BOLD)
    ui.emit(ui.RULE, ui.BOLD)
    colors = {"ok": ui.GREEN, "warn": ui.YELLOW, "fail": ui.RED, "skip": ui.DIM}
    for i, (title, status, dt) in enumerate(results, start=1):
        ui.emit(f"  {i:>2}. [{status.upper():^4}] {title:<44} {dt:6.1f} s", colors.get(status))
    ui.emit(f"\n  Install log: {ui.log_path}")
    if not aborted:
        ui.say(f"Answers saved for a re-run: {ANSWERS}")
        ui.say(f"Remove the configuration: sudo python3 {os.path.abspath(__file__)} --uninstall")


# ============================================================= UNINSTALL ====
def uninstall(ui):
    ui.banner(f"{WIZARD}.py {WIZARD_VERSION}: UNINSTALL" + (" (dry run)" if ui.dry_run else ""),
              "Removes the wizard's configuration blocks. Packages and data are kept.")
    prev = json.loads(read_text(ANSWERS) or "{}")
    targets = []
    for engine in ("redis", "valkey"):
        lay = LAYOUT[engine]
        for conf, svc, block in ((lay["conf"], lay["service"], BLOCK),
                                 (lay["sentinel_conf"], lay["sentinel_service"], SENTINEL_BLOCK)):
            if f">>> {block} (managed by fpolicy-av wizard) >>>" in read_text(conf):
                targets.append((conf, svc, block))
    ui.section("Plan")
    for conf, svc, _ in targets:
        ui.kv(conf, f"remove the managed block, then stop/restart {svc}")
    if not targets:
        ui.say("no managed blocks found")
    if not targets or not ui.ask_yes("Proceed?", not ui.interactive):
        sys.exit("nothing to do" if not targets else "aborted")
    stop = ui.ask_yes("Stop and disable the services as well (otherwise they restart with "
                      "the package defaults)?", True)
    for conf, svc, block in targets:
        ui.section(conf)
        cur = read_text(conf)
        text = remove_managed_block(cur, block)
        if block == SENTINEL_BLOCK:
            m = re.search(r"(?m)^sentinel monitor (\S+)", cur)
            if m:
                # state lines Sentinel generated for our master would stop it starting
                text = re.sub(rf"(?m)^sentinel \S+ {re.escape(m.group(1))}\b.*\n?", "", text)
            text = restore_default_master(text)
        ui.write_file(conf, text, 0o640, show="diff")
        ui.run(["systemctl", "disable", "--now", svc] if stop else ["systemctl", "restart", svc],
               check=False)
    if prev.get("valkey_source"):
        ui.note("Valkey was built from source: binaries stay in /usr/local/bin and the units "
                "in /etc/systemd/system/valkey-*.service. Remove them by hand if needed.")
    ui.remove_path(ANSWERS)
    ui.say("Packages kept. To remove them: sudo apt-get purge redis-server redis-sentinel "
           "redis-tools valkey-server valkey-sentinel valkey-tools")


# ================================================================== MAIN ====
def main():
    ap = argparse.ArgumentParser(description="Install the shared verdict cache "
                                             "(Redis or Valkey) for the FPolicy AV scanners.")
    ap.add_argument("--dry-run", action="store_true",
                    help="ask the questions and show every step, change nothing")
    ap.add_argument("--answers", metavar="FILE",
                    help=f"reuse answers from FILE (default: {ANSWERS} if it exists)")
    ap.add_argument("--non-interactive", action="store_true",
                    help="no prompts: use the answers file; password from FPAV_CACHE_PASSWORD")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the wizard's configuration blocks")
    ap.add_argument("--version", action="version", version=f"{WIZARD}.py {WIZARD_VERSION}")
    args = ap.parse_args()
    if sys.platform != "linux":
        sys.exit("Run this on the Linux cache host.")
    if os.geteuid() != 0 and not args.dry_run:
        sys.exit("Run as root:  sudo python3 " + " ".join(sys.argv))
    ui = UI(dry_run=args.dry_run, interactive=not args.non_interactive)
    ui.open_log(SETUP_LOG_DIR, WIZARD)
    if args.uninstall:
        uninstall(ui)
        return
    ui.banner(f"FPolicy AV verdict cache - {WIZARD}.py {WIZARD_VERSION}"
              + ("   [DRY RUN]" if args.dry_run else ""),
              "Redis or Valkey as primary, replica or Sentinel.\n"
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
    ui.emit("")
    if not ui.ask_yes(f"Run the {len(STEPS)} install steps"
                      + (" in dry-run mode" if ui.dry_run else "") + " now?", True):
        sys.exit("aborted: nothing was changed")
    execute(ui, plan, facts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
