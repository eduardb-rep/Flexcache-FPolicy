"""End-to-end test of fpolicy_av_linux.py against a real clamd (and optionally Redis).

It starts its own server instances on 127.0.0.1:19898-19905, plays ONTAP against
them and checks every decision path: clean, EICAR, cached, large file in the
background, close + rescan, '&' in names, probe codes, unmapped shares, path
traversal, sync deadline with a hung clamd, clamd down (fail open / closed),
fail-soft cache and a shared verdict between two scanners.

Run it on a scanner (as root, or as fpolicy-av, so it can reach the clamd socket):
    python3 tests/test_server.py ./fpolicy_av_linux.py /run/clamav/clamd.ctl /tmp/fpav-test [redis_port]
The redis_port test needs a Redis/Valkey on 127.0.0.1; if it requires authentication, put
the secret in the FPAV_TEST_REDIS_AUTH environment variable.
It writes about 110 MB of test files (including EICAR test files) under the work directory.
"""
import os
import socket
import subprocess
import sys
import threading
import time

SRV, CLAMD, WORK = sys.argv[1], sys.argv[2], sys.argv[3]
REDIS_PORT = sys.argv[4] if len(sys.argv) > 4 else None
REDIS_AUTH = os.environ.get("FPAV_TEST_REDIS_AUTH", "")
sys.path.insert(0, os.path.dirname(SRV))
import fpolicy_av_linux as f  # noqa: E402

PY = sys.executable
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


def mkshares():
    base = os.path.join(WORK, "mnt", "svm1")
    for d in ("share1/dir", "share2"):
        os.makedirs(os.path.join(base, d), exist_ok=True)
    with open(os.path.join(base, "share1", "clean.txt"), "w") as fh:
        fh.write("hello\n")
    with open(os.path.join(base, "share1", "dir", "eicar.txt"), "wb") as fh:
        fh.write(f.EICAR)
    big = os.path.join(base, "share1", "big_eicar.bin")
    if not os.path.exists(big):
        with open(big, "wb") as fh:
            fh.write(os.urandom(110 * 1024 * 1024) + f.EICAR)
    with open(os.path.join(base, "share2", "readme.txt"), "w") as fh:
        fh.write("share2\n")
    return base


def write_conf(name, port, extra_server="", cache="backend = none\n", sock=CLAMD,
               shares=None):
    base = os.path.join(WORK, "mnt", "svm1")
    shares = shares or (f"svm1/share1 = {base}/share1\n"
                        f"share2 = {base}/share2\n")
    conf = os.path.join(WORK, f"{name}.conf")
    opts = {"bind": "127.0.0.1", "port": str(port), "sync_limit_mb": "100",
            "sync_deadline_s": "15", "fail_mode": "open", "workers": "8",
            "bg_workers": "2", "stats_interval_s": "3", "raw_dump": "2",
            "log": f"{WORK}/log/{name}.log", "require_cifs_mount": "false",
            "probe_codes": "true"}
    for ln in extra_server.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            opts[k.strip()] = v.strip()
    server_txt = "".join(f"{k} = {v}\n" for k, v in opts.items())
    with open(conf, "w") as fh:
        fh.write(f"""[server]
{server_txt}
[clamd]
socket = {sock}

[cache]
{cache}
[shares]
{shares}""")
    return conf


def start(conf, port):
    p = subprocess.Popen([PY, SRV, "-c", conf], stdout=subprocess.DEVNULL,
                         stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server did not start")


class Ontap:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=60)
        self.s.sendall(f.frame("NEGO_REQ", "<Handshake><VsUUID>u</VsUUID><PolicyName>p"
                               "</PolicyName><SessionId>s</SessionId><ProtVersion>"
                               "<Vers>1.0</Vers><Vers>1.2</Vers></ProtVersion></Handshake>"))
        self.nego = f.split_message(f.read_message(self.s))
        self.n = 0
        self.lock = threading.Lock()
        self.replies = {}
        self.cv = threading.Condition()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                m = f.read_message(self.s)
            except OSError:
                return
            if m is None:
                return
            notf, body = f.split_message(m)
            with self.cv:
                self.replies[f.tag(body, "ReqId")] = (notf, f.tag(body, "NotfResp"), time.time())
                self.cv.notify_all()

    def send(self, display, req_type="SMB_OPEN"):
        with self.lock:
            self.n += 1
            rid = str(self.n)
        body = (f"<FscreenReq><ReqId>{rid}</ReqId><ReqType>{req_type}</ReqType><NotfInfo>"
                f"<SmbOpenReq><CommonInfo><ProtCommonInfo><ClientIp>10.0.0.9</ClientIp>"
                f"</ProtCommonInfo><DisplayPath>{display}</DisplayPath></CommonInfo>"
                f"</SmbOpenReq></NotfInfo></FscreenReq>")
        t0 = time.time()
        self.s.sendall(f.frame("SCREEN_REQ", body))
        return rid, t0

    def wait(self, rid, timeout=60):
        with self.cv:
            self.cv.wait_for(lambda: rid in self.replies, timeout)
            return self.replies.get(rid)

    def screen(self, display, req_type="SMB_OPEN", timeout=60):
        rid, t0 = self.send(display, req_type)
        r = self.wait(rid, timeout)
        return (r[1], r[2] - t0) if r else (None, None)


def main():
    os.makedirs(os.path.join(WORK, "log"), exist_ok=True)
    mkshares()

    # ---------------- basic decisions -------------------------------------
    conf = write_conf("basic", 19898)
    out = subprocess.run([PY, SRV, "-c", conf, "--check"], capture_output=True, text=True)
    print(out.stdout)
    check("--check exits 0", out.returncode == 0, out.stderr[-300:])
    p = start(conf, 19898)
    try:
        out = subprocess.run([PY, SRV, "-c", conf, "--selftest"], capture_output=True, text=True)
        print(out.stdout)
        check("--selftest exits 0", out.returncode == 0)
        o = Ontap(19898)
        check("handshake 1.2", o.nego[0] == "NEGO_RESP" and f.tag(o.nego[1], "ProtVersion") == "1.2")
        code, dt = o.screen(r"\\SVM1\share1\clean.txt")
        check("clean -> allow", code == "1", f"{dt:.3f}s")
        code, dt = o.screen(r"\\SVM1\share1\dir\eicar.txt")
        check("eicar -> deny", code == "2", f"{dt:.3f}s")
        code, dt = o.screen(r"\\OTHERNAME\share1\dir\eicar.txt")
        check("server name mismatch -> matched by share, deny", code == "2")
        code, dt = o.screen(r"\\SVM1\share2\readme.txt")
        check("unqualified share key -> allow", code == "1")
        code, dt = o.screen(r"\\SVM1\nosuchshare\x.txt")
        check("unmapped share -> allow (fail open)", code == "1")
        code, dt = o.screen(r"\\SVM1\share1\..\..\..\etc\passwd")
        check("path traversal -> unmapped, not read", code == "1")
        code, dt = o.screen(r"\\SVM1\share1\missing.txt")
        check("missing file -> allow (new file)", code == "1")
        code, dt = o.screen(r"\\SVM1\share1\__probe2__.txt")
        check("probe code 2", code == "2")
        code, dt = o.screen(r"\\SVM1\share1\big_eicar.bin")
        check("large file first open -> allow at once", code == "1" and dt < 2, f"{dt:.3f}s")
        code2 = None
        for _ in range(60):
            time.sleep(1)
            code2, _ = o.screen(r"\\SVM1\share1\big_eicar.bin")
            if code2 == "2":
                break
        check("large file later open -> deny after background scan", code2 == "2")
        # close-with-modification triggers background rescan
        path = os.path.join(WORK, "mnt", "svm1", "share1", "dir", "written.txt")
        with open(path, "w") as fh:
            fh.write("clean first\n")
        code, _ = o.screen(r"\\SVM1\share1\dir\written.txt")
        check("new clean file -> allow", code == "1")
        with open(path, "wb") as fh:
            fh.write(b"prefix " + f.EICAR + b" suffix")
        code, dt = o.screen(r"\\SVM1\share1\dir\written.txt", "SMB_CLOSE")
        check("close -> allow at once", code == "1" and dt < 1, f"{dt:.3f}s")
        time.sleep(2)
        code, _ = o.screen(r"\\SVM1\share1\dir\written.txt")
        check("open after infected write -> deny", code == "2")
        # file name with '&': ONTAP escapes it in the XML
        with open(os.path.join(WORK, "mnt", "svm1", "share1", "R&D eicar.txt"), "wb") as fh:
            fh.write(f.EICAR)
        code, _ = o.screen(r"\\SVM1\share1\R&amp;D eicar.txt")
        check("'&amp;' in DisplayPath is decoded (R&D file denied)", code == "2")
        # concurrency: 40 parallel requests
        rids = [o.send(r"\\SVM1\share1\clean.txt")[0] for _ in range(40)]
        got = [o.wait(r, 30) for r in rids]
        check("40 parallel screens answered", all(g and g[1] == "1" for g in got))
        time.sleep(4)
    finally:
        p.terminate()
        p.wait()
    logtxt = open(os.path.join(WORK, "log", "basic.log")).read()
    print(logtxt[-4000:])
    check("STATS line logged", "STATS" in logtxt)
    check("mismatch warning logged", "matched by share name only" in logtxt)

    # ---------------- deadline: clamd that never answers ------------------
    hang = os.path.join(WORK, "hang.sock")
    if os.path.exists(hang):
        os.unlink(hang)
    hs = socket.socket(socket.AF_UNIX)
    hs.bind(hang)
    hs.listen(50)
    held = []

    def acceptor():
        while True:
            try:
                c, _ = hs.accept()
                held.append(c)   # never reply
            except OSError:
                return
    threading.Thread(target=acceptor, daemon=True).start()
    for mode, expect in (("open", "1"), ("closed", "2")):
        conf = write_conf(f"deadline_{mode}", 19899,
                          extra_server=f"sync_deadline_s = 2\nfail_mode = {mode}\n"
                                       "sigver_refresh_s = 0\n", sock=hang)
        p = start(conf, 19899)
        try:
            o = Ontap(19899)
            code, dt = o.screen(r"\\SVM1\share1\clean.txt", timeout=30)
            check(f"hung clamd, fail_mode={mode} -> {expect} at deadline",
                  code == expect and 1.5 < dt < 4, f"{dt:.2f}s")
        finally:
            p.terminate()
            p.wait()

    # ---------------- clamd down ------------------------------------------
    for mode, expect in (("open", "2"), ("closed", "2")):
        # open: built-in matcher still catches EICAR; closed: undecided -> deny
        conf = write_conf(f"down_{mode}", 19900, extra_server=f"fail_mode = {mode}\n",
                          sock=os.path.join(WORK, "nope.sock"))
        p = start(conf, 19900)
        try:
            o = Ontap(19900)
            code, _ = o.screen(r"\\SVM1\share1\dir\eicar.txt")
            check(f"clamd down, fail_mode={mode}, eicar -> {expect}", code == expect)
            code, _ = o.screen(r"\\SVM1\share1\clean.txt")
            exp = "1" if mode == "open" else "2"
            check(f"clamd down, fail_mode={mode}, clean -> {exp}", code == exp)
        finally:
            p.terminate()
            p.wait()

    # ---------------- password with % (interpolation) ---------------------
    conf = write_conf("pct", 19901, cache="backend = redis\nhost = 127.0.0.1\nport = 1\n"
                                         "password = ab%cd%%ef\n")
    p = start(conf, 19901)
    try:
        o = Ontap(19901)
        code, dt = o.screen(r"\\SVM1\share1\clean.txt")
        check("password with % parses; cache down is fail-soft", code == "1" and dt < 2,
              f"{dt:.3f}s")
    finally:
        p.terminate()
        p.wait()

    # ---------------- shared cache with real redis ------------------------
    if REDIS_PORT:
        cache = (f"backend = redis\nhost = 127.0.0.1\nport = {REDIS_PORT}\n"
                 + (f"password = {REDIS_AUTH}\n" if REDIS_AUTH else "") + "ttl_seconds = 600\n")
        conf_a = write_conf("cache_a", 19902, cache=cache)
        conf_b = write_conf("cache_b", 19903, cache=cache)
        pa, pb = start(conf_a, 19902), start(conf_b, 19903)
        try:
            oa, ob = Ontap(19902), Ontap(19903)
            code, _ = oa.screen(r"\\SVM1\share1\dir\eicar.txt")
            check("scanner A denies eicar", code == "2")
            code, _ = ob.screen(r"\\SVM1\share1\dir\eicar.txt")
            check("scanner B denies eicar", code == "2")
        finally:
            pa.terminate()
            pb.terminate()
            pa.wait()
            pb.wait()
        log_b = open(os.path.join(WORK, "log", "cache_b.log")).read()
        check("scanner B used the shared verdict", "cached shared" in log_b)
        out = subprocess.run([PY, SRV, "-c", conf_a, "--check"], capture_output=True, text=True)
        check("--check sees the shared cache", "write test" in out.stdout, out.stdout[-400:])

    # ---------------- probe codes off, mount readiness ---------------------
    for mode, expect in (("open", "1"), ("closed", "2")):
        conf = write_conf(f"strict_{mode}", 19905,
                          extra_server=f"probe_codes = false\nrequire_cifs_mount = true\n"
                                       f"fail_mode = {mode}\n")
        p = start(conf, 19905)
        try:
            o = Ontap(19905)
            with open(os.path.join(WORK, "mnt", "svm1", "share1", "x__probe1__.txt"), "wb") as fh:
                fh.write(f.EICAR)
            code, _ = o.screen(r"\\SVM1\share1\x__probe1__.txt")
            check(f"probe codes off: __probe1__ file is scanned ({mode}) -> 2", code == "2")
            code, _ = o.screen(r"\\SVM1\share1\not_there.txt")
            check(f"share not on a CIFS mount, missing file, fail_mode={mode} -> {expect}",
                  code == expect)
        finally:
            p.terminate()
            p.wait()
    log_s = open(os.path.join(WORK, "log", "strict_open.log")).read()
    check("mount problem logged", "is not on a CIFS mount" in log_s)

    # ---------------- unit checks ------------------------------------------
    cfg = f.load_config(write_conf("unit", 19904, extra_server="allowed_clients = 10.1.0.0/16, 192.168.2.132\n"))
    srv = f.Server(cfg)
    check("allowed: 10.1.2.3", srv.client_allowed("10.1.2.3"))
    check("allowed: loopback", srv.client_allowed("127.0.0.1"))
    check("allowed: v4-mapped", srv.client_allowed("::ffff:192.168.2.132"))
    check("rejected: 10.2.0.1", not srv.client_allowed("10.2.0.1"))

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


main()
