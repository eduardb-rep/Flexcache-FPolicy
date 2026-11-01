"""Lab-only ONTAP FPolicy external server that screens SMB opens on FlexCache
shares with ClamAV (clamd INSTREAM), falling back to a built-in EICAR matcher.

ONTAP connects to this server (synchronous external engine, XML format):
  - SCREEN_REQ SMB_OPEN  -> read the file via an out-of-scope path (c$), scan,
                            answer ALLOW or DENY.
  - SCREEN_REQ SMB_CLOSE -> answer ALLOW immediately, rescan in the background
                            (close-with-modification only) and log detections.

Pilot kit changes (1 Nov 2026):
  - XML entities in DisplayPath are decoded ("R&amp;D.docx" -> "R&D.docx"), so file
    names containing & < > are scanned like any other file.
  - The __probeN__ file-name diagnostic is off unless --probe-codes is given.

Not a supported NetApp antivirus integration.
"""

import argparse
import html
import logging
import os
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

XML_DECL = b'<?xml version="1.0"?>'
SEPARATOR = b"\n\n"
PREFERRED_VERSIONS = ["1.2", "1.1", "1.0", "2.0", "3.0"]

# EICAR test string, stored as hex so this script is not itself flagged.
EICAR = bytes.fromhex(
    "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
    "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
)

log = logging.getLogger("fpolicy-av")
raw_log = logging.getLogger("fpolicy-av.raw")


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


class Scanner:
    def __init__(self, clamd_host, clamd_port, max_bytes):
        self.clamd = (clamd_host, clamd_port)
        self.max_bytes = max_bytes
        self.cache = {}
        self.lock = threading.Lock()

    def _clamd_instream(self, data):
        with socket.create_connection(self.clamd, timeout=15) as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 65536):
                chunk = data[i:i + 65536]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                part = s.recv(4096)
                if not part:
                    break
                reply += part
        reply = reply.rstrip(b"\0").decode(errors="replace")
        if reply.endswith("FOUND"):
            return True, reply.split(":", 1)[1].strip()[:-len(" FOUND")], "clamav"
        if reply.endswith("OK"):
            return False, None, "clamav"
        raise RuntimeError(f"clamd: {reply}")

    def scan_bytes(self, data):
        try:
            return self._clamd_instream(data)
        except (OSError, RuntimeError) as e:
            log.debug("clamd unavailable (%s), using built-in matcher", e)
            if EICAR in data:
                return True, "Builtin.EICAR-Test-File", "builtin"
            return False, None, "builtin"

    def scan_path(self, unc, force=False):
        st = os.stat(unc)
        key = (unc.lower(), st.st_size, st.st_mtime_ns)
        if not force:
            with self.lock:
                if key in self.cache:
                    return self.cache[key] + ("cached",)
        if st.st_size > self.max_bytes:
            verdict = (False, None, "skipped-too-large")
        else:
            with open(unc, "rb") as f:
                data = f.read(self.max_bytes + 1)
            verdict = self.scan_bytes(data)
        with self.lock:
            self.cache[key] = verdict
        return verdict + ("scanned",)


class Server:
    def __init__(self, args):
        self.args = args
        self.share_map = {}
        for item in args.share_map:
            share, base = item.split("=", 1)
            self.share_map[share.lower()] = base.rstrip("\\")
        self.scanner = Scanner(args.clamd_host, args.clamd_port, args.max_mb * 1024 * 1024)
        self.pool = ThreadPoolExecutor(max_workers=16)
        self.raw_dumped = 0

    def resolve(self, body):
        # ONTAP sends well-formed XML: "&" in a file name arrives as "&amp;"
        display = html.unescape(tag(body, "DisplayPath") or "")
        parts = display.lstrip("\\").split("\\", 2)
        if len(parts) >= 2 and parts[1].lower() in self.share_map:
            rel = parts[2] if len(parts) == 3 else ""
            return display, self.share_map[parts[1].lower()] + ("\\" + rel if rel else "")
        return display, None

    def respond(self, conn, send_lock, req_id, req_type, code):
        body = (f"<FscreenResp><ReqId>{req_id}</ReqId><ReqType>{req_type}</ReqType>"
                f"<NotfResp>{code}</NotfResp></FscreenResp>")
        with send_lock:
            conn.sendall(frame("SCREEN_RESP", body))

    def probe_code(self, display):
        m = re.search(r"__probe(\d)__", display, re.IGNORECASE)
        return int(m.group(1)) if m else None

    def handle_screen(self, conn, send_lock, body):
        req_id = tag(body, "ReqId") or "0"
        req_type = tag(body, "ReqType") or "UNKNOWN"
        client = tag(body, "ClientIp") or "?"
        display, unc = self.resolve(body)
        if self.raw_dumped < self.args.raw_dump:
            self.raw_dumped += 1
            raw_log.info("ReqId=%s ReqType=%s\n%s", req_id, req_type, body)

        probe = self.probe_code(display) if self.args.probe_codes else None
        if probe is not None:
            log.warning("PROBE   %-10s code=%d  %s", req_type, probe, display)
            self.respond(conn, send_lock, req_id, req_type, probe)
            return

        allow, deny = self.args.allow_code, self.args.deny_code
        if req_type.endswith("_CLOSE"):
            self.respond(conn, send_lock, req_id, req_type, allow)
            if unc:
                self.pool.submit(self.post_close_scan, display, unc, client)
            return

        if not unc:
            log.info("ALLOW   %-10s (unmapped path) %s", req_type, display)
            self.respond(conn, send_lock, req_id, req_type, allow)
            return

        t0 = time.time()
        try:
            infected, sig, engine, how = self.scanner.scan_path(unc)
        except FileNotFoundError:
            self.respond(conn, send_lock, req_id, req_type, allow)
            log.info("ALLOW   %-10s (new file) %s", req_type, display)
            return
        except OSError as e:
            self.respond(conn, send_lock, req_id, req_type, allow)
            log.error("ALLOW   %-10s (scan error: %s) %s", req_type, e, display)
            return
        ms = (time.time() - t0) * 1000
        if infected:
            self.respond(conn, send_lock, req_id, req_type, deny)
            log.warning("DENY    %-10s %s  [%s via %s, %s, %.0f ms] client=%s",
                        req_type, display, sig, engine, how, ms, client)
        else:
            self.respond(conn, send_lock, req_id, req_type, allow)
            log.info("ALLOW   %-10s %s  [clean via %s, %s, %.0f ms]", req_type, display, engine, how, ms)

    def post_close_scan(self, display, unc, client):
        try:
            infected, sig, engine, _ = self.scanner.scan_path(unc, force=True)
        except OSError as e:
            log.error("CLOSE   scan error %s: %s", display, e)
            return
        if infected:
            log.warning("INFECTED WRITTEN  %s  [%s via %s] client=%s (next open will be denied)",
                        display, sig, engine, client)
        else:
            log.info("CLOSE   %s clean (%s)", display, engine)

    def handle_conn(self, conn, addr):
        log.info("ONTAP connected from %s:%s", *addr)
        conn.settimeout(600)
        send_lock = threading.Lock()
        try:
            while True:
                msg = read_message(conn)
                if msg is None:
                    break
                parts = msg.split(SEPARATOR, 1)
                header = parts[0].decode(errors="replace")
                body = parts[1].rstrip(b"\x00\r\n").decode(errors="replace") if len(parts) > 1 else ""
                notf = tag(header, "NotfType")
                if notf == "NEGO_REQ":
                    versions = re.findall(r"<Vers>(.*?)</Vers>", body)
                    ver = next((v for v in PREFERRED_VERSIONS if v in versions), "1.0")
                    resp = (f"<HandshakeResp><VsUUID>{tag(body, 'VsUUID')}</VsUUID>"
                            f"<PolicyName>{tag(body, 'PolicyName')}</PolicyName>"
                            f"<SessionId>{tag(body, 'SessionId')}</SessionId>"
                            f"<ProtVersion>{ver}</ProtVersion></HandshakeResp>")
                    with send_lock:
                        conn.sendall(frame("NEGO_RESP", resp))
                    log.info("Handshake: policy=%s versions=%s -> %s",
                             tag(body, "PolicyName"), versions, ver)
                elif notf == "SCREEN_REQ":
                    self.pool.submit(self.safe_screen, conn, send_lock, body)
                elif notf in ("KEEP_ALIVE", "KEEP_ALIVE_REQ"):
                    log.debug("keep-alive from %s", addr[0])
                elif notf == "ALERT_MSG":
                    log.warning("ALERT from ONTAP: %s", body)
                else:
                    log.info("Message %s: %s", notf, body[:300])
        except (OSError, ValueError) as e:
            log.error("connection %s: %s", addr, e)
        finally:
            conn.close()
            log.info("ONTAP disconnected %s:%s", *addr)

    def safe_screen(self, conn, send_lock, body):
        try:
            self.handle_screen(conn, send_lock, body)
        except Exception:
            log.exception("screen handler failed")

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.args.bind, self.args.port))
        srv.listen(16)
        log.info("Listening on %s:%d  allow=%d deny=%d  shares=%s",
                 self.args.bind, self.args.port, self.args.allow_code, self.args.deny_code, self.share_map)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle_conn, args=(conn, addr), daemon=True).start()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9898)
    p.add_argument("--share-map", nargs="+", required=True,
                   help=r"share=UNC base, e.g. av_wa_cache=\\cluster2_svm1\c$\av_wa_cache")
    p.add_argument("--clamd-host", default="127.0.0.1")
    p.add_argument("--clamd-port", type=int, default=3310)
    p.add_argument("--max-mb", type=int, default=25)
    p.add_argument("--allow-code", type=int, default=1)
    p.add_argument("--deny-code", type=int, default=2)
    p.add_argument("--raw-dump", type=int, default=10)
    p.add_argument("--probe-codes", action="store_true",
                   help="lab diagnostic only: a file named *__probeN__* is answered with code N, unscanned")
    p.add_argument("--log", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fpolicy_av.log"))
    args = p.parse_args()

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    for name, path in (("fpolicy-av", args.log), ("fpolicy-av.raw", args.log.replace(".log", "_raw.log"))):
        lg = logging.getLogger(name)
        lg.setLevel(logging.INFO)
        lg.propagate = False
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(fmt)
        lg.addHandler(fh)
        if name == "fpolicy-av":
            sh = logging.StreamHandler()
            sh.setFormatter(fmt)
            lg.addHandler(sh)
    Server(args).serve()


if __name__ == "__main__":
    main()
