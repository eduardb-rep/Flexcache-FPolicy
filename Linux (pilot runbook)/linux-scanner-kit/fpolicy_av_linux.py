#!/usr/bin/env python3
"""Lab-only ONTAP FPolicy external server for Linux (version 2).

ONTAP (synchronous external engine, XML) sends a SCREEN_REQ for every SMB open
and every close-with-modification on the shares in the policy scope. This
server reads the file from a local read-only CIFS mount of the SVM's scan$
share, asks ClamAV (clamd) and answers allow (1) or deny (2).

  - Open of a file at or under sync_limit_mb: scanned while ONTAP holds the
    open. If the scan can't finish before sync_deadline_s (ONTAP cancels at
    20 s), the server answers by fail_mode and finishes the scan in the
    background.
  - Open of a larger file: allowed at once, scanned in the background. The
    next open is denied if the file is infected.
  - Close of a modified file: allowed at once, rescanned in the background.
  - Verdicts are cached locally and, optionally, in Redis/Valkey. The key is
    path + size + mtime + clamd signature version.

clamd is reached over its local UNIX socket with fdpass (FILDES), so files are
never copied into this process. INSTREAM and a built-in EICAR matcher are the
fallbacks (the EICAR matcher only when fail_mode = open).

Modes:
  fpolicy_av_linux.py --config FILE              run the server
  fpolicy_av_linux.py --config FILE --check      verbose health check, then exit
  fpolicy_av_linux.py --config FILE --selftest   act as ONTAP against the
                                                 running server, then exit

Lab tool. Not a NetApp-supported antivirus integration.
"""

from __future__ import annotations

import argparse
import array
import configparser
import html
import ipaddress
import logging
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from xml.sax.saxutils import escape as xml_escape

VERSION = "2.0"
XML_DECL = b'<?xml version="1.0"?>'
SEPARATOR = b"\n\n"
PREFERRED_VERSIONS = ["1.2", "1.1", "1.0", "2.0", "3.0"]
ONTAP_CANCEL_S = 20          # ONTAP's default cancel-request timeout

# EICAR test string as hex, so this file is not itself flagged.
EICAR = bytes.fromhex(
    "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
    "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
)

log = logging.getLogger("fpolicy-av")
raw_log = logging.getLogger("fpolicy-av.raw")


# ----------------------------------------------------------------- framing ---
def tag(xml, name):
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.DOTALL)
    return m.group(1).strip() if m else None


def recvall(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_message(sock):
    """One FPolicy frame: '"' + 4-byte big-endian length + '"' + payload."""
    while True:
        b = recvall(sock, 1)
        if b is None:
            return None
        if b == b'"':
            break
    hdr = recvall(sock, 4)
    if hdr is None:
        return None
    length = struct.unpack(">I", hdr)[0]
    if recvall(sock, 1) is None:
        return None
    if length == 0 or length > 10 * 1024 * 1024:
        raise ValueError(f"invalid frame length {length}")
    return recvall(sock, length)


def frame(notf_type, body_xml):
    body = XML_DECL + body_xml.encode("utf-8")
    header = XML_DECL + (
        f"<Header><NotfType>{notf_type}</NotfType>"
        f"<ContentLen>{len(body)}</ContentLen><DataFormat>XML</DataFormat></Header>"
    ).encode("utf-8")
    payload = header + SEPARATOR + body + b"\x00"
    return b'"' + struct.pack(">I", len(payload)) + b'"' + payload


def split_message(msg):
    parts = msg.split(SEPARATOR, 1)
    header = parts[0].decode(errors="replace")
    body = parts[1].rstrip(b"\x00\r\n").decode(errors="replace") if len(parts) > 1 else ""
    return tag(header, "NotfType"), body


# ------------------------------------------------------------------ clamd ---
def parse_clamd_reply(reply):
    """Turn a clamd reply into (infected, signature); raise on errors."""
    reply = reply.rstrip("\x00").strip()
    if reply.endswith(" FOUND"):
        # "fd[9]: Win.Test.EICAR_HDB-1 FOUND" or "stream: ... FOUND"
        text = reply.split(":", 1)[1] if ":" in reply else reply
        return True, text.strip()[: -len(" FOUND")].strip()
    if reply.endswith("OK"):
        return False, None
    raise RuntimeError(f"clamd: {reply or 'empty reply'}")


class Scanner:
    """clamd client: fdpass preferred, INSTREAM fallback, EICAR last resort."""

    def __init__(self, clamd_socket, clamd_host, clamd_port, max_bytes,
                 builtin_fallback=True):
        self.clamd_socket = clamd_socket
        self.clamd_tcp = (clamd_host, clamd_port) if clamd_port else None
        self.max_bytes = max_bytes
        self.builtin_fallback = builtin_fallback

    def unix_ok(self):
        return bool(self.clamd_socket) and os.path.exists(self.clamd_socket)

    def _connect(self, timeout):
        if self.unix_ok():
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(self.clamd_socket)
            return s
        if self.clamd_tcp:
            s = socket.create_connection(self.clamd_tcp, timeout=timeout)
            s.settimeout(timeout)
            return s
        raise OSError(f"clamd socket {self.clamd_socket} not found")

    @staticmethod
    def _reply(s):
        reply = b""
        while not reply.endswith(b"\0"):
            part = s.recv(4096)
            if not part:
                break
            reply += part
        return reply.rstrip(b"\x00").decode(errors="replace")

    def command(self, cmd, timeout=5):
        with self._connect(timeout) as s:
            s.sendall(b"z" + cmd.encode() + b"\0")
            return self._reply(s)

    def ping(self, timeout=2):
        try:
            return self.command("PING", timeout) == "PONG"
        except OSError:
            return False

    def version(self, timeout=5):
        """'ClamAV 1.5.4/27800' (engine/signature db) or 'unknown'."""
        try:
            text = self.command("VERSION", timeout)
        except OSError:
            return "unknown"
        if not text.startswith("ClamAV"):
            # Ubuntu ships EnableVersionCommand false; the wizard turns it on.
            log.warning("clamd VERSION unavailable (%s): verdicts will not be "
                        "invalidated by signature updates. Set "
                        "'EnableVersionCommand yes' in clamd.conf.", text)
            return "unknown"
        parts = text.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else text

    def scan_fd(self, path, timeout):
        """fdpass: open the file here and hand clamd the descriptor.

        Protocol (clamd man page): send the FILDES command on its own, then a
        separate packet with at least one dummy byte that carries the file
        descriptor as SCM_RIGHTS ancillary data. Sending both in one message
        makes clamd answer "PROTOCOL ERROR: ancillary data sent without FILDES".
        """
        if not self.unix_ok():
            raise OSError("fdpass needs the clamd UNIX socket")
        fd = os.open(path, os.O_RDONLY)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(self.clamd_socket)
                s.sendall(b"zFILDES\0")
                s.sendmsg([b"\0"],
                          [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array("i", [fd]))])
                reply = self._reply(s)
        finally:
            os.close(fd)
        infected, sig = parse_clamd_reply(reply)
        return infected, sig, "clamav-fdpass"

    def scan_instream(self, path, timeout):
        with open(path, "rb") as f:
            data = f.read(self.max_bytes + 1)
        with self._connect(timeout) as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 65536):
                chunk = data[i:i + 65536]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            reply = self._reply(s)
        infected, sig = parse_clamd_reply(reply)
        return infected, sig, "clamav-instream"

    def scan(self, path, timeout, large=False):
        """fdpass, then INSTREAM (not for large files), then EICAR matcher."""
        try:
            return self.scan_fd(path, timeout)
        except socket.timeout:
            raise
        except (OSError, RuntimeError) as e:
            if large:
                raise
            log.debug("fdpass failed (%s), trying INSTREAM", e)
        try:
            return self.scan_instream(path, timeout)
        except socket.timeout:
            raise
        except (OSError, RuntimeError) as e:
            if not self.builtin_fallback:
                raise RuntimeError(f"clamd unavailable: {e}")
            log.debug("clamd unavailable (%s), using built-in EICAR matcher", e)
        with open(path, "rb") as f:
            data = f.read(self.max_bytes + 1)
        if EICAR in data:
            return True, "Builtin.EICAR-Test-File", "builtin"
        return False, None, "builtin"


# ----------------------------------------------------------- verdict cache ---
class VerdictCache:
    """In-process LRU in front of an optional shared Redis/Valkey store.

    The shared store is best effort: 0.5 s timeouts, no client retries, a
    circuit breaker on errors and reconnects in a background thread, so a
    cache outage never holds a user's open.
    """

    def __init__(self, cfg):
        self.cfg = dict(cfg)
        self.ttl = int(self.cfg.get("ttl_seconds", "86400"))
        self.local = OrderedDict()
        self.local_cap = int(self.cfg.get("local_entries", "50000"))
        self.lock = threading.Lock()
        self.redis = None
        self.backend = self.cfg.get("backend", "none").lower()
        self.enabled = self.backend in ("redis", "valkey")
        self.last_try = 0.0
        self.connecting = False
        self.last_error = None
        self.hits_local = self.hits_shared = self.misses = 0
        if self.enabled:
            self._connect()

    def describe(self):
        if not self.enabled:
            return "local only"
        target = (f"sentinel {self.cfg.get('sentinel')} / {self.cfg.get('sentinel_master')}"
                  if self.cfg.get("sentinel") else
                  f"{self.cfg.get('host', '127.0.0.1')}:{self.cfg.get('port', '6379')}")
        state = "connected" if self.redis is not None else f"down ({self.last_error})"
        return f"{self.backend} {target}, {state}"

    @staticmethod
    def _client_kwargs():
        kw = {"socket_timeout": 0.5, "socket_connect_timeout": 0.5,
              "retry_on_timeout": False}
        try:  # redis-py >= 4.1: disable the built-in retry/backoff
            from redis.backoff import NoBackoff
            from redis.retry import Retry
            kw["retry"] = Retry(NoBackoff(), 0)
        except ImportError:
            pass
        return kw

    def _connect(self):
        self.last_try = time.time()
        try:
            import redis  # Valkey is wire-compatible with redis-py
            from redis.sentinel import Sentinel
        except ImportError:
            log.warning("python3-redis not installed: local verdict cache only")
            self.enabled = False
            self.last_error = "python3-redis missing"
            return
        cfg = self.cfg
        password = cfg.get("password") or None
        kw = self._client_kwargs()
        try:
            sentinels = cfg.get("sentinel", "").strip()
            if sentinels:
                hosts = []
                for h in sentinels.split(","):
                    h = h.strip()
                    if h:
                        host, _, port = h.rpartition(":")
                        hosts.append((host, int(port)))
                skw = {"socket_timeout": 0.5, "socket_connect_timeout": 0.5}
                if password:
                    skw["password"] = password
                sentinel = Sentinel(hosts, socket_timeout=0.5, sentinel_kwargs=skw)
                client = sentinel.master_for(
                    cfg.get("sentinel_master", "fpolicy-cache"), password=password, **kw)
            else:
                client = redis.Redis(host=cfg.get("host", "127.0.0.1"),
                                     port=int(cfg.get("port", "6379")),
                                     password=password, **kw)
            client.ping()
            self.redis = client
            self.last_error = None
            log.info("verdict cache connected: %s", self.describe())
        except Exception as e:
            self.redis = None
            self.last_error = str(e) or e.__class__.__name__
            log.warning("verdict cache unreachable (%s): local cache only, "
                        "retrying every 30 s", self.last_error)

    def _connect_bg(self):
        try:
            self._connect()
        finally:
            self.connecting = False

    def _shared(self):
        """Current client, or None; schedules a background reconnect when down."""
        if self.redis is None and self.enabled and not self.connecting \
                and time.time() - self.last_try > 30:
            self.connecting = True
            threading.Thread(target=self._connect_bg, daemon=True).start()
        return self.redis

    def _trip(self, e):
        if self.redis is not None:
            log.warning("verdict cache error (%s): local cache only until reconnect", e)
        self.redis = None
        self.last_error = str(e)
        self.last_try = time.time()

    def get(self, key):
        with self.lock:
            if key in self.local:
                self.local.move_to_end(key)
                self.hits_local += 1
                return self.local[key], "local"
        client = self._shared()
        if client is not None:
            try:
                raw = client.get("verdict:" + key)
            except Exception as e:
                self._trip(e)
                raw = None
            if raw is not None:
                val = raw.decode() if isinstance(raw, bytes) else raw
                verdict = (val.startswith("1"), val[2:] or None)
                self._put_local(key, verdict)
                self.hits_shared += 1
                return verdict, "shared"
        self.misses += 1
        return None, None

    def set(self, key, infected, sig):
        self._put_local(key, (infected, sig))
        if key.endswith("|unknown"):
            return  # clamd version not known yet: don't share a key nobody will look up
        client = self._shared()
        if client is not None:
            try:
                client.set("verdict:" + key, ("1:" if infected else "0:") + (sig or ""),
                           ex=self.ttl)
            except Exception as e:
                self._trip(e)

    def _put_local(self, key, value):
        with self.lock:
            self.local[key] = value
            self.local.move_to_end(key)
            while len(self.local) > self.local_cap:
                self.local.popitem(last=False)


# ------------------------------------------------------------------ config ---
def load_config(path):
    # interpolation=None: passwords may contain '%'.
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(path):
        raise SystemExit(f"config not found or unreadable: {path}")
    for section in ("server", "clamd", "shares"):
        if not cfg.has_section(section):
            raise SystemExit(f"{path}: missing [{section}] section")
    return cfg


def parse_networks(text):
    nets = []
    for item in re.split(r"[,\s]+", text or ""):
        if item:
            nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def parse_share_map(section):
    """[shares] keys are 'share' or 'cifsserver/share'; values are local paths."""
    share_map = {}
    for key, value in section.items():
        key = key.strip().lower()
        server, _, share = key.rpartition("/")
        share_map[(server or None, share)] = os.path.normpath(value.strip())
    return share_map


class Stats:
    FIELDS = ("screens", "allow", "deny", "undecided", "unmapped", "scans_sync",
              "scans_bg", "deadline", "large")

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.counts = dict.fromkeys(self.FIELDS, 0)
        self.since = time.time()

    def inc(self, name):
        with self.lock:
            self.counts[name] += 1

    def snapshot_and_reset(self):
        with self.lock:
            snap, elapsed = dict(self.counts), time.time() - self.since
            self.reset()
        return snap, elapsed


# ------------------------------------------------------------------ server ---
class Server:
    def __init__(self, cfg):
        s = cfg["server"]
        self.bind = s.get("bind", "0.0.0.0")
        self.port = int(s.get("port", "9898"))
        self.allow_code = int(s.get("allow_code", "1"))
        self.deny_code = int(s.get("deny_code", "2"))
        self.sync_limit = max(1, min(int(s.get("sync_limit_mb", "100")), 100)) * 1024 * 1024
        self.sync_deadline = max(1.0, min(float(s.get("sync_deadline_s", "15")),
                                          ONTAP_CANCEL_S - 1))
        self.fail_closed = s.get("fail_mode", "open").strip().lower() == "closed"
        self.raw_dump = int(s.get("raw_dump", "10"))
        self.raw_dumped = 0
        self.raw_lock = threading.Lock()
        self.bg_timeout = float(s.get("bg_timeout_s", "900"))
        self.stats_interval = int(s.get("stats_interval_s", "300"))
        self.sigver_interval = int(s.get("sigver_refresh_s", "300"))
        try:
            self.allowed = parse_networks(s.get("allowed_clients", ""))
        except ValueError as e:
            raise SystemExit(f"[server] allowed_clients: {e}")
        # lab diagnostics only: a file name containing __probeN__ gets code N, unscanned
        self.probe_codes = s.get("probe_codes", "false").strip().lower() in ("1", "true", "yes")
        # a missing file only means "new file" if the scan$ mount is really there
        self.require_mount = s.get("require_cifs_mount", "true").strip().lower() in (
            "1", "true", "yes")
        self.base_ok = {}

        self.share_map = parse_share_map(cfg["shares"])
        self.mismatch_warned = set()
        c = cfg["clamd"]
        tcp_port = c.get("tcp_port", "").strip()
        self.scanner = Scanner(c.get("socket", "/run/clamav/clamd.ctl"),
                               c.get("tcp_host", "127.0.0.1"),
                               int(tcp_port) if tcp_port else None,
                               self.sync_limit, builtin_fallback=not self.fail_closed)
        self.cache = VerdictCache(cfg["cache"] if cfg.has_section("cache") else {})
        # Short timeout: clamd may still be loading its database at boot; the
        # housekeeping thread retries every 30 s until it answers.
        self.sigver = self.scanner.version(timeout=2)
        self.pool = ThreadPoolExecutor(max_workers=int(s.get("workers", "16")),
                                       thread_name_prefix="screen")
        self.bg_pool = ThreadPoolExecutor(max_workers=int(s.get("bg_workers", "4")),
                                          thread_name_prefix="bg")
        self.inflight = set()
        self.inflight_lock = threading.Lock()
        self.bg_queued = 0
        self.stats = Stats()

    # ---- path resolution ----
    def resolve(self, display):
        """\\\\SERVER\\share\\dir\\file -> local path under the scan$ mount."""
        parts = display.lstrip("\\").split("\\", 2)
        if len(parts) < 2 or not parts[1]:
            return None, "no share in DisplayPath"
        server, share = parts[0].lower(), parts[1].lower()
        rel = parts[2] if len(parts) == 3 else ""
        base = self.share_map.get((server, share)) or self.share_map.get((None, share))
        if base is None:
            candidates = [b for (srv, sh), b in self.share_map.items() if sh == share]
            if len(candidates) == 1:
                base = candidates[0]
                if (server, share) not in self.mismatch_warned:
                    self.mismatch_warned.add((server, share))
                    log.warning("share %s: CIFS server '%s' is not in [shares]; "
                                "matched by share name only", share, server)
        if base is None:
            if candidates:
                return None, (f"share '{share}' is configured for several CIFS servers and "
                              f"'{server}' is not one of them")
            return None, f"share '{share}' not in [shares]"
        rel = rel.replace("\\", "/").strip("/")
        path = os.path.normpath(os.path.join(base, rel)) if rel else base
        if path != base and not path.startswith(base.rstrip("/") + "/"):
            return None, "path escapes the share root"
        return path, None

    def share_base(self, path):
        for base in self.share_map.values():
            if path == base or path.startswith(base.rstrip("/") + "/"):
                return base
        return None

    def base_ready(self, path):
        """(True, '') when the share folder exists on a live CIFS mount (cached 10 s)."""
        base = self.share_base(path)
        if base is None:
            return False, "no share folder for this path"
        now = time.time()
        hit = self.base_ok.get(base)
        if hit and now - hit[0] < 10:
            return hit[1], hit[2]
        if not os.path.isdir(base):
            res = (False, f"share folder {base} missing: is the scan$ share mounted?")
        elif self.require_mount and mount_of(base)[1] not in ("cifs", "smb3", "smb2"):
            res = (False, f"{base} is not on a CIFS mount (scan$ not mounted?)")
        else:
            res = (True, "")
        if not res[0] and (not hit or hit[1]):
            log.error("SHARE   %s", res[1])
        self.base_ok[base] = (now, res[0], res[1])
        return res

    def cache_key(self, path):
        st = os.stat(path)
        # SMB is case-insensitive, so the key is too.
        return f"{path.lower()}|{st.st_size}|{st.st_mtime_ns}|{self.sigver}", st.st_size

    # ---- FPolicy response ----
    def respond(self, conn, send_lock, req_id, req_type, code):
        body = (f"<FscreenResp><ReqId>{req_id}</ReqId><ReqType>{req_type}</ReqType>"
                f"<NotfResp>{code}</NotfResp></FscreenResp>")
        with send_lock:
            conn.sendall(frame("SCREEN_RESP", body))
        self.stats.inc("allow" if code == self.allow_code else "deny")

    @staticmethod
    def probe_code(display):
        m = re.search(r"__probe(\d)__", display, re.IGNORECASE)
        return int(m.group(1)) if m else None

    def undecided(self, conn, send_lock, req_id, req_type, why, display):
        """Scanner couldn't decide: follow fail_mode (open = allow, closed = deny)."""
        code = self.deny_code if self.fail_closed else self.allow_code
        self.respond(conn, send_lock, req_id, req_type, code)
        self.stats.inc("undecided")
        log.error("%s %-10s %s  [undecided: %s, fail_mode=%s]",
                  "DENY   " if self.fail_closed else "ALLOW  ", req_type, display, why,
                  "closed" if self.fail_closed else "open")

    # ---- screen handling ----
    def handle_screen(self, conn, send_lock, body, t_recv):
        req_id = tag(body, "ReqId") or "0"
        req_type = tag(body, "ReqType") or "UNKNOWN"
        client = tag(body, "ClientIp") or "?"
        # ONTAP sends well-formed XML: '&' in a file name arrives as '&amp;'
        display = html.unescape(tag(body, "DisplayPath") or "")
        self.stats.inc("screens")
        with self.raw_lock:
            dump = self.raw_dumped < self.raw_dump
            if dump:
                self.raw_dumped += 1
        if dump:
            raw_log.info("ReqId=%s ReqType=%s\n%s", req_id, req_type, body)

        probe = self.probe_code(display) if self.probe_codes else None
        if probe is not None:
            log.warning("PROBE   %-10s code=%d  %s", req_type, probe, display)
            self.respond(conn, send_lock, req_id, req_type, probe)
            return

        allow, deny = self.allow_code, self.deny_code
        path, why = self.resolve(display)

        if req_type.endswith("_CLOSE"):
            self.respond(conn, send_lock, req_id, req_type, allow)
            if path:
                self.submit_bg(display, path, client, "close")
            return

        if not path:
            self.stats.inc("unmapped")
            code = deny if self.fail_closed else allow
            self.respond(conn, send_lock, req_id, req_type, code)
            log.warning("%s %-10s %s  [unmapped: %s; not scanned]",
                        "DENY   " if self.fail_closed else "ALLOW  ", req_type, display, why)
            return

        try:
            key, size = self.cache_key(path)
        except FileNotFoundError:
            ready, why = self.base_ready(path)
            if not ready:
                self.undecided(conn, send_lock, req_id, req_type, why, display)
                return
            self.respond(conn, send_lock, req_id, req_type, allow)
            log.info("ALLOW   %-10s %s  [not on the scan$ mount yet: new file]",
                     req_type, display)
            return
        except OSError as e:
            self.undecided(conn, send_lock, req_id, req_type, f"stat error: {e}", display)
            return

        verdict, layer = self.cache.get(key)
        if verdict is not None:
            infected, sig = verdict
            self.respond(conn, send_lock, req_id, req_type, deny if infected else allow)
            log.log(logging.WARNING if infected else logging.INFO,
                    "%s %-10s %s  [%s, cached %s, %.0f ms]%s",
                    "DENY   " if infected else "ALLOW  ", req_type, display,
                    sig if infected else "clean", layer, (time.time() - t_recv) * 1000,
                    f" client={client}" if infected else "")
            return

        if size > self.sync_limit:
            self.respond(conn, send_lock, req_id, req_type, allow)
            self.stats.inc("large")
            log.info("ALLOW   %-10s %s  [large %d MB > sync limit, scanning in background]",
                     req_type, display, size // (1024 * 1024))
            self.submit_bg(display, path, client, "large")
            return

        remaining = self.sync_deadline - (time.time() - t_recv)
        if remaining < 0.5:
            self.undecided(conn, send_lock, req_id, req_type,
                           "queued past the sync deadline", display)
            self.submit_bg(display, path, client, "deadline")
            return

        t0 = time.time()
        self.stats.inc("scans_sync")
        try:
            infected, sig, engine = self.scanner.scan(path, timeout=remaining)
        except socket.timeout:
            self.stats.inc("deadline")
            self.undecided(conn, send_lock, req_id, req_type,
                           f"scan not finished after {self.sync_deadline:.0f} s", display)
            self.submit_bg(display, path, client, "deadline")
            return
        except (OSError, RuntimeError) as e:
            self.undecided(conn, send_lock, req_id, req_type, f"scan error: {e}", display)
            return
        self.cache.set(key, infected, sig)
        ms = (time.time() - t0) * 1000
        total = (time.time() - t_recv) * 1000
        if infected:
            self.respond(conn, send_lock, req_id, req_type, deny)
            log.warning("DENY    %-10s %s  [%s via %s, scan %.0f ms, total %.0f ms] client=%s",
                        req_type, display, sig, engine, ms, total, client)
        else:
            self.respond(conn, send_lock, req_id, req_type, allow)
            log.info("ALLOW   %-10s %s  [clean via %s, scan %.0f ms, total %.0f ms]",
                     req_type, display, engine, ms, total)

    # ---- background scans ----
    def submit_bg(self, display, path, client, reason):
        with self.inflight_lock:
            self.bg_queued += 1
        self.bg_pool.submit(self.background_scan, display, path, client, reason)

    def background_scan(self, display, path, client, reason):
        with self.inflight_lock:
            self.bg_queued -= 1
        try:
            key, size = self.cache_key(path)
        except OSError as e:
            log.error("BG      stat error %s: %s", display, e)
            return
        with self.inflight_lock:
            if key in self.inflight:
                return  # this file version is already being scanned
            self.inflight.add(key)
        try:
            self.stats.inc("scans_bg")
            t0 = time.time()
            try:
                infected, sig, engine = self.scanner.scan(
                    path, timeout=self.bg_timeout, large=size > self.sync_limit)
            except (OSError, RuntimeError) as e:
                log.error("BG      scan error (%s) %s: %s", reason, display, e)
                return
            self.cache.set(key, infected, sig)
            if infected:
                log.warning("INFECTED (%s)  %s  [%s via %s, %.1f s] client=%s "
                            "(next open denied)", reason, display, sig, engine,
                            time.time() - t0, client)
            else:
                log.info("BG OK   (%s)  %s  [clean via %s, %.1f s]",
                         reason, display, engine, time.time() - t0)
        finally:
            with self.inflight_lock:
                self.inflight.discard(key)

    # ---- housekeeping threads ----
    def housekeeping(self):
        next_stats = time.time() + self.stats_interval
        next_sig = time.time() + (30 if self.sigver == "unknown" else self.sigver_interval)
        while True:
            time.sleep(5)
            now = time.time()
            if self.sigver_interval and now >= next_sig:
                v = self.scanner.version()
                if v != "unknown" and v != self.sigver:
                    log.info("clamd signature version: %s -> %s "
                             "(verdicts cached for the old version are no longer used)",
                             self.sigver, v)
                    self.sigver = v
                # retry quickly while clamd is still loading its database
                next_sig = now + (30 if self.sigver == "unknown" else self.sigver_interval)
            if self.stats_interval and now >= next_stats:
                next_stats = now + self.stats_interval
                snap, elapsed = self.stats.snapshot_and_reset()
                with self.inflight_lock:
                    running, queued = len(self.inflight), self.bg_queued
                log.info("STATS   last %.0f s: %s | bg running=%d queued=%d | "
                         "cache hits local=%d shared=%d misses=%d (%s) | sig=%s",
                         elapsed, " ".join(f"{k}={v}" for k, v in snap.items()),
                         running, queued, self.cache.hits_local, self.cache.hits_shared,
                         self.cache.misses, self.cache.describe(), self.sigver)

    # ---- connection loop ----
    def client_allowed(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr.is_loopback or not self.allowed or str(addr) == self.bind:
            return True
        return any(addr in net for net in self.allowed)

    def handle_conn(self, conn, addr):
        local = ipaddress.ip_address(addr[0]).is_loopback
        log.info("FPolicy client connected from %s:%s%s", addr[0], addr[1],
                 " (local self-test)" if local else "")
        conn.settimeout(600)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        send_lock = threading.Lock()
        try:
            while True:
                msg = read_message(conn)
                if msg is None:
                    break
                t_recv = time.time()
                notf, body = split_message(msg)
                if notf == "NEGO_REQ":
                    versions = re.findall(r"<Vers>(.*?)</Vers>", body)
                    ver = next((v for v in PREFERRED_VERSIONS if v in versions), "1.0")
                    resp = (f"<HandshakeResp><VsUUID>{tag(body, 'VsUUID')}</VsUUID>"
                            f"<PolicyName>{tag(body, 'PolicyName')}</PolicyName>"
                            f"<SessionId>{tag(body, 'SessionId')}</SessionId>"
                            f"<ProtVersion>{ver}</ProtVersion></HandshakeResp>")
                    with send_lock:
                        conn.sendall(frame("NEGO_RESP", resp))
                    log.info("Handshake from %s: policy=%s versions=%s -> %s",
                             addr[0], tag(body, "PolicyName"), versions, ver)
                elif notf == "SCREEN_REQ":
                    self.pool.submit(self.safe_screen, conn, send_lock, body, t_recv)
                elif notf in ("KEEP_ALIVE", "KEEP_ALIVE_REQ"):
                    log.debug("keep-alive from %s", addr[0])
                elif notf == "ALERT_MSG":
                    log.warning("ALERT from %s: %s", addr[0], body)
                else:
                    log.info("Message %s from %s: %s", notf, addr[0], body[:300])
        except (OSError, ValueError) as e:
            log.error("connection %s:%s: %s", addr[0], addr[1], e)
        finally:
            conn.close()
            log.info("FPolicy client disconnected %s:%s", addr[0], addr[1])

    def safe_screen(self, conn, send_lock, body, t_recv):
        try:
            self.handle_screen(conn, send_lock, body, t_recv)
        except Exception:
            log.exception("screen handler failed")

    def serve(self):
        family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port))
        srv.listen(64)
        log.info("fpolicy_av_linux %s listening on %s:%d | allow=%d deny=%d | "
                 "sync<=%d MB, deadline %.0f s | fail_mode=%s | clamd=%s (%s) | "
                 "cache=%s | allowed_clients=%s | shares=%s",
                 VERSION, self.bind, self.port, self.allow_code, self.deny_code,
                 self.sync_limit // (1024 * 1024), self.sync_deadline,
                 "closed" if self.fail_closed else "open", self.scanner.clamd_socket,
                 self.sigver, self.cache.describe(),
                 ",".join(map(str, self.allowed)) or "any",
                 {f"{k[0] + '/' if k[0] else ''}{k[1]}": v for k, v in self.share_map.items()})
        threading.Thread(target=self.housekeeping, daemon=True, name="housekeeping").start()
        while True:
            conn, addr = srv.accept()
            if not self.client_allowed(addr[0]):
                log.warning("rejected connection from %s (not in allowed_clients)", addr[0])
                conn.close()
                continue
            threading.Thread(target=self.handle_conn, args=(conn, addr),
                             daemon=True).start()


# ------------------------------------------------------------ --check mode ---
def find_sample_file(base, limit=2000, small=1024 * 1024):
    """A non-empty file under base (bounded walk), preferring one <= 1 MB."""
    seen, fallback = 0, None
    for root, dirs, files in os.walk(base):
        dirs.sort()
        for name in sorted(files):
            seen += 1
            p = os.path.join(root, name)
            try:
                size = os.path.getsize(p) if os.path.isfile(p) else 0
            except OSError:
                size = 0
            if 0 < size <= small:
                return p
            if size and fallback is None:
                fallback = p
            if seen >= limit:
                return fallback
    return fallback


def mount_of(path):
    """(mount point, fstype) for path, from /proc/mounts."""
    best = ("/", "?")
    try:
        with open("/proc/mounts") as f:
            for line in f:
                fields = line.split()
                mnt = fields[1].replace("\\040", " ")
                if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) \
                        and len(mnt) >= len(best[0]):
                    best = (mnt, fields[2])
    except OSError:
        pass
    return best


def run_check(cfg, config_path):
    """Verbose health check of everything the server depends on."""
    ok = True

    def line(status, msg):
        print(f"  [{status:^4}] {msg}")

    print(f"fpolicy_av_linux {VERSION} health check")
    print(f"  config: {config_path}")
    s = cfg["server"]
    print(f"  listen {s.get('bind', '0.0.0.0')}:{s.get('port', '9898')}, "
          f"sync limit {s.get('sync_limit_mb', '100')} MB, "
          f"deadline {s.get('sync_deadline_s', '15')} s, fail_mode {s.get('fail_mode', 'open')}")

    print("\nclamd")
    c = cfg["clamd"]
    scanner = Scanner(c.get("socket", "/run/clamav/clamd.ctl"), "127.0.0.1", None,
                      100 * 1024 * 1024, builtin_fallback=False)
    if scanner.unix_ok():
        line("OK", f"socket {scanner.clamd_socket} exists")
    else:
        line("FAIL", f"socket {scanner.clamd_socket} not found (is clamav-daemon running?)")
        ok = False
    clamd_ok = scanner.ping()
    if clamd_ok:
        line("OK", "PING -> PONG")
        v = scanner.version()
        line("OK" if v != "unknown" else "WARN", f"VERSION -> {v}")
        tmpdir = tempfile.mkdtemp(prefix="fpav-check-")
        try:
            for label, content, expect in (("EICAR test file", EICAR, True),
                                           ("clean test file", b"fpolicy-av clean test\n", False)):
                p = os.path.join(tmpdir, "sample.txt")
                with open(p, "wb") as f:
                    f.write(content)
                try:
                    t0 = time.time()
                    infected, sig, engine = scanner.scan_fd(p, timeout=30)
                    good = infected == expect
                    line("OK" if good else "FAIL",
                         f"fdpass scan of {label}: "
                         f"{'FOUND ' + sig if infected else 'clean'} "
                         f"({engine}, {(time.time() - t0) * 1000:.0f} ms)")
                    ok = ok and good
                except (OSError, RuntimeError) as e:
                    line("FAIL", f"fdpass scan of {label}: {e}")
                    ok = False
                os.unlink(p)
        finally:
            os.rmdir(tmpdir)
    else:
        line("FAIL", "clamd does not answer PING")
        ok = False

    print("\nshares (from [shares])")
    for (server, share), base in parse_share_map(cfg["shares"]).items():
        name = f"{server + '/' if server else ''}{share}"
        mnt, fstype = mount_of(base)
        if not os.path.isdir(base):
            line("FAIL", f"{name} -> {base}: not a directory (is the scan$ share mounted?)")
            ok = False
            continue
        try:
            entries = len(os.listdir(base))
        except OSError as e:
            line("FAIL", f"{name} -> {base}: cannot list ({e})")
            ok = False
            continue
        status = "OK" if fstype in ("cifs", "smb3") else "WARN"
        line(status, f"{name} -> {base}: {entries} entries, on {mnt} ({fstype})")
        sample = find_sample_file(base)
        if sample:
            try:
                with open(sample, "rb") as f:
                    f.read(1)
                line("OK", f"  read test: {sample}")
            except OSError as e:
                line("FAIL", f"  read test: {sample}: {e}")
                ok = False
                continue
            # the real path end to end: open on the mount, pass the fd, clamd reads
            # it (AppArmor re-checks passed files against clamd's profile)
            if clamd_ok:
                try:
                    t0 = time.time()
                    infected, sig, engine = scanner.scan_fd(sample, timeout=120)
                    line("WARN" if infected else "OK",
                         f"  fdpass scan of that file: {'FOUND ' + sig if infected else 'clean'}"
                         f" ({(time.time() - t0) * 1000:.0f} ms)")
                except (OSError, RuntimeError) as e:
                    line("FAIL", f"  fdpass scan of that file failed: {e} (AppArmor rule for "
                                 f"the mount point missing?)")
                    ok = False
        else:
            line("WARN", "  no non-empty file found to test reading (empty share?)")

    print("\nverdict cache")
    cache = VerdictCache(cfg["cache"] if cfg.has_section("cache") else {})
    if not cache.enabled:
        line("OK", f"shared cache: {cache.describe()}")
    elif cache.redis is not None:
        line("OK", f"shared cache: {cache.describe()}")
        try:
            info = cache.redis.info("replication")
            line("OK", f"  role={info.get('role')} connected_slaves="
                       f"{info.get('connected_slaves', '-')}")
            cache.redis.set("verdict:__fpav_check__", "0:", ex=60)
            line("OK", "  write test: SET verdict:__fpav_check__ ok")
        except Exception as e:
            line("WARN", f"  {e}")
    else:
        line("WARN", f"shared cache: {cache.describe()} (the server still works: "
                     "local cache only)")

    print("\nresult:", "all checks passed" if ok else "some checks FAILED")
    return 0 if ok else 1


# --------------------------------------------------------- --selftest mode ---
def run_selftest(cfg):
    """Act as ONTAP: handshake + SCREEN_REQs against the running server."""
    s = cfg["server"]
    host = "127.0.0.1" if s.get("bind", "0.0.0.0") in ("0.0.0.0", "::", "") else s["bind"]
    port = int(s.get("port", "9898"))
    print(f"FPolicy self-test against {host}:{port} (this process plays ONTAP)")
    share_map = parse_share_map(cfg["shares"])
    (server, share), base = next(iter(share_map.items()))
    server = (server or "SELFTEST").upper()
    sample = find_sample_file(base)
    closed = s.get("fail_mode", "open").strip().lower() == "closed"
    tests = []   # (label, DisplayPath, accepted codes, expectation text)
    if sample:
        rel = os.path.relpath(sample, base).replace("/", "\\")
        tests.append(("real file on the scan$ mount", f"\\\\{server}\\{share}\\{rel}",
                      ("1", "2"), "1 if clean, 2 if infected"))
    else:
        print(f"  [WARN] no sample file under {base}; testing the share root instead")
        tests.append(("share root", f"\\\\{server}\\{share}", ("1",), "1"))
    tests.append(("file that does not exist yet", f"\\\\{server}\\{share}\\__fpav_selftest_new__.txt",
                  ("1",), "1: a new file"))
    tests.append(("share not in [shares]", f"\\\\{server}\\__not_configured__\\x.txt",
                  ("2",) if closed else ("1",), "2 (fail closed)" if closed else "1 (fail open)"))
    try:
        sock = socket.create_connection((host, port), timeout=60)
    except OSError as e:
        print(f"  [FAIL] cannot connect: {e} (is fpolicy-av running?)")
        return 1
    failed = 0
    with sock:
        t0 = time.time()
        sock.sendall(frame("NEGO_REQ",
                           "<Handshake><VsUUID>selftest</VsUUID><PolicyName>selftest</PolicyName>"
                           "<SessionId>selftest</SessionId><ProtVersion><Vers>1.0</Vers>"
                           "<Vers>1.1</Vers><Vers>1.2</Vers></ProtVersion></Handshake>"))
        notf, body = split_message(read_message(sock) or b"")
        if notf != "NEGO_RESP":
            print(f"  [FAIL] handshake: expected NEGO_RESP, got {notf}")
            return 1
        print(f"  [ OK ] handshake: NEGO_RESP, ProtVersion {tag(body, 'ProtVersion')} "
              f"({(time.time() - t0) * 1000:.0f} ms)")
        for i, (label, display, accepted, expect) in enumerate(tests, start=1):
            req = (f"<FscreenReq><ReqId>{i}</ReqId><ReqType>SMB_OPEN</ReqType><NotfInfo>"
                   f"<SmbOpenReq><CommonInfo><ProtCommonInfo><ClientIp>127.0.0.1</ClientIp>"
                   f"</ProtCommonInfo><DisplayPath>{xml_escape(display)}</DisplayPath>"
                   f"</CommonInfo></SmbOpenReq></NotfInfo></FscreenReq>")
            t0 = time.time()
            sock.sendall(frame("SCREEN_REQ", req))
            notf, body = split_message(read_message(sock) or b"")
            ms = (time.time() - t0) * 1000
            code = tag(body, "NotfResp")
            if notf != "SCREEN_RESP" or tag(body, "ReqId") != str(i):
                print(f"  [FAIL] {label}: unexpected reply {notf} {body[:200]}")
                return 1
            good = code in accepted
            failed += not good
            print(f"  [{' OK ' if good else 'FAIL'}] {label}: {display}\n"
                  f"         -> NotfResp {code} in {ms:.0f} ms (expected {expect})")
    print("  The decisions are also in the server log.")
    return 1 if failed else 0


# -------------------------------------------------------------------- main ---
def setup_logging(path, level="info", console=True):
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    lvl = getattr(logging, level.upper(), logging.INFO)
    for name, p in (("fpolicy-av", path),
                    ("fpolicy-av.raw", path.replace(".log", "_raw.log"))):
        lg = logging.getLogger(name)
        lg.setLevel(lvl)
        lg.propagate = False
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        fh = logging.FileHandler(p, encoding="utf-8")
        fh.setFormatter(fmt)
        lg.addHandler(fh)
        if console and name == "fpolicy-av":
            sh = logging.StreamHandler()
            sh.setFormatter(fmt)
            lg.addHandler(sh)


def main():
    p = argparse.ArgumentParser(description="Linux FPolicy AV server (lab)")
    p.add_argument("-c", "--config", default="/etc/fpolicy-av/scanner.conf")
    p.add_argument("--check", action="store_true",
                   help="verbose health check of clamd, shares and cache, then exit")
    p.add_argument("--selftest", action="store_true",
                   help="play ONTAP against the running server, then exit")
    p.add_argument("--version", action="version", version=f"fpolicy_av_linux {VERSION}")
    args = p.parse_args()

    cfg = load_config(args.config)
    if args.check:
        logging.basicConfig(level=logging.WARNING, format="  [WARN] %(message)s")
        sys.exit(run_check(cfg, args.config))
    if args.selftest:
        sys.exit(run_selftest(cfg))
    setup_logging(cfg["server"].get("log", "/var/log/fpolicy-av/fpolicy_av.log"),
                  cfg["server"].get("log_level", "info"))
    Server(cfg).serve()


if __name__ == "__main__":
    main()
