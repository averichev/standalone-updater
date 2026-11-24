#!/usr/bin/env python3
"""Disposable independent-consumer E2E. Linux: --native; macOS: Docker by default.

Only temporary keys, configuration, processes and data are used. Never imports
MockPort or contacts a production release server. Requirements: Python >=3.11,
Cargo/Rust >=1.91, C compiler, CMake and OpenSSL 3 (or Docker).
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "44872c33-bef2-4c34-9290-29d762b6d965"
TOKEN = "temporary-demo-admin-token-only-for-e2e"
SECRET = "ephemeral-sentinel-not-for-journals"
URL_SECRET = "ephemeral-transport-token-not-for-jobs"
VARIANTS = [("old", "0.5.0", "good", "demo-format-v1"),
            ("good", "0.6.0", "good", "demo-format-v1"),
            ("next", "0.7.0", "good", "demo-format-v1"),
            ("fail-start", "0.6.0", "fail-start", "demo-format-v1"),
            ("fail-health", "0.6.0", "fail-health", "demo-format-v1"),
            ("incompatible", "0.6.0", "good", "incompatible-format-v2"),
            ("unclean-old", "0.5.0", "unclean-shutdown", "demo-format-v1")]
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def eventually(function, predicate=bool, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = function()
            if predicate(last):
                return last
        except (OSError, urllib.error.URLError, ValueError) as error:
            last = type(error).__name__
        time.sleep(0.05)
    raise AssertionError(f"condition timed out; last result: {last}")


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def build(fixtures):
    fixtures.mkdir(parents=True, exist_ok=True)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=ROOT))
    target = Path(metadata["target_directory"])
    for name, version, behavior, compatibility in VARIANTS:
        env = dict(os.environ, UPDATER_EXAMPLE_VERSION=version, UPDATER_EXAMPLE_BEHAVIOR=behavior, UPDATER_EXAMPLE_DATA=compatibility)
        print(f"Building independent consumer: {name} {version}", flush=True)
        subprocess.run(["cargo", "build", "--locked", "--profile", "e2e", "--features", "linux-runtime", "--example", "axum-service"], cwd=ROOT, env=env, check=True)
        shutil.copy2(target / "e2e/examples/axum-service", fixtures / name)


class Source:
    def __init__(self, fixtures, key_dir):
        self.fixtures = fixtures
        self.key_dir = key_dir
        self.key = key_dir / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)], check=True, capture_output=True)
        self.key.chmod(0o600)
        public = subprocess.check_output(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"])
        assert public[:12].hex() == "302a300506032b6570032100"
        self.public_key = dict(kty="OKP", crv="Ed25519", x=b64(public[12:]))
        info = json.loads(subprocess.check_output([fixtures / "old", "--standalone-updater-build-info"]))
        self.target = "linux-" + info["rust_target"].split("-")[0]
        self.port = unused_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.documents = {}
        kid = b64(hashlib.sha256(json.dumps(dict(crv="Ed25519", kty="OKP", x=self.public_key["x"]), separators=(",", ":")).encode()).digest())
        for name, version, _, _ in VARIANTS[1:]:
            if name == "unclean-old":
                continue
            payload = dict(schema_version=1, application_id=PRODUCT, version=version, os="linux", arch=self.target.removeprefix("linux-"), size_bytes=(fixtures / name).stat().st_size, sha256=digest(fixtures / name))
            header = dict(alg="EdDSA", typ="releases-standalone+jws", kid=kid)
            value = b64(json.dumps(header, separators=(",", ":")).encode()) + "." + b64(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = key_dir / "input"
            signing_input.write_text(value)
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(signing_input)])
            self.documents[name] = dict(version=version, url=f"{self.base}/artifact/{name}?ticket={URL_SECRET}", signed_metadata=value + "." + b64(signature))
        self.server = None
        self.variant = "good"
        self.delay = 0.001
        self.downloads = 0
        self.start()

    def start(self):
        if self.server:
            return
        source = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def document(self, data, status=200):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                if path.startswith("/descriptor/"):
                    assert path == "/descriptor/" + source.target
                    current = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["current_version"][0]
                    document = source.documents[source.variant]
                    if tuple(map(int, current.split("."))) >= tuple(map(int, document["version"].split("."))):
                        self.send_response(204)
                        self.end_headers()
                    else:
                        self.document(document)
                elif path == "/manifest":
                    document = source.documents[source.variant]
                    self.document(dict(schema_version=2, releases=[dict(version=document["version"], notes="Disposable signed release", artifacts=[dict(purpose="executable", target=source.target, download_url=document["url"])])]))
                elif path == "/artifact/" + source.variant:
                    source.downloads += 1
                    binary = source.fixtures / source.variant
                    self.send_response(200)
                    self.send_header("Content-Length", str(binary.stat().st_size))
                    self.end_headers()
                    try:
                        with binary.open("rb") as stream:
                            while block := stream.read(64 * 1024):
                                self.wfile.write(block)
                                self.wfile.flush()
                                time.sleep(source.delay)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                else:
                    self.send_error(404)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        server = self.server
        self.server = None
        if server:
            server.shutdown()
            server.server_close()
            self.thread.join()

    def select(self, variant="good", delay=0.001):
        self.start()
        self.variant = variant
        self.delay = delay
        self.downloads = 0


class App:
    def __init__(self, root, fixtures, source, mode="supervisor", readonly=False, unprivileged=False, initial="old", manual_only=False):
        self.root = root
        self.root.mkdir(mode=0o700)
        self.work = root / "working directory"
        self.work.mkdir(mode=0o700)
        self.install_dir = root / "application directory"
        self.install_dir.mkdir(mode=0o700)
        self.binary = self.install_dir / "arbitrary application name"
        shutil.copy2(fixtures / initial, self.binary)
        self.data = self.work / "customer.data"
        self.data.write_bytes(b"User data must stay byte-identical\0\xff")
        self.config = self.work / "application.json"
        self.updates = self.work / "updates"
        self.port = unused_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.mode = mode
        self.settings = dict(source=dict(product_id=PRODUCT, manifest_url=source.base + "/manifest", descriptor_url=source.base + "/descriptor/{target}", public_key=source.public_key, allowed_download_origins=[source.base], max_artifact_bytes=128 * 1024 * 1024), mode=mode, updates_directory=str(self.updates), data_file=str(self.data), address=f"127.0.0.1:{self.port}", health_timeout_ms=3000)
        self.settings["manual_data_policy"] = manual_only
        self.config.write_text(json.dumps(self.settings))
        self.config.chmod(0o600)
        self.original = [digest(self.config), digest(self.data)]
        self.env = dict(os.environ, UPDATER_DEMO_CONFIG=str(self.config), UPDATER_DEMO_ADMIN_TOKEN=TOKEN, DEMO_SENTINEL_SECRET=SECRET)
        self.arguments = ["--label", "argument with spaces", "--secret-for-test", SECRET]
        self.identity = {}
        if unprivileged:
            assert os.geteuid() == 0
            self.root.chmod(0o755)
            self.install_dir.chmod(0o555)
            self.binary.chmod(0o555)
            for path in [self.work, self.data, self.config]:
                os.chown(path, 65534, 65534)
            self.identity = dict(user=65534, group=65534, extra_groups=[])
        elif readonly:
            self.install_dir.chmod(0o500)
        self.log = (root / "process.log").open("wb")
        self.process = None
        self.start()

    @property
    def installed(self):
        return self.updates / "runtime" / self.binary.name if self.mode == "supervisor" else self.binary

    def start(self):
        self.process = subprocess.Popen([self.binary, *self.arguments], cwd=self.work, env=self.env, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log, start_new_session=True, **self.identity)
        eventually(lambda: self.call("/ready"), timeout=20)

    def call(self, path, value=None, method=None, authorized=True, headers=None):
        headers = dict(headers or {})
        if authorized:
            headers["Authorization"] = "Bearer " + TOKEN
        if value is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=json.dumps(value).encode() if value is not None else None, headers=headers, method=method)
        with HTTP.open(request, timeout=3) as response:
            return json.load(response)

    def status(self):
        return self.call("/update")

    def durable(self):
        return json.loads((self.updates / "status.json").read_text())

    def wait_stage(self, stage):
        return eventually(self.status, lambda r: r["status"]["state"] == stage, timeout=35)

    def prepare(self):
        checked = self.call("/update/check", {}, "POST")
        available = self.wait_stage("available")["status"]
        assert available["operation_id"] == checked["operation_id"]
        request = dict(check_id=checked["operation_id"], version=available["available"]["version"])
        self.call("/update/prepare", request, "POST")
        self.wait_stage("prepared")
        return checked["operation_id"]

    def install(self, operation):
        # A prepared status can become visible just before its guard is released.
        return eventually(lambda: self.call("/update/install", dict(operation_id=operation), "POST"), timeout=5)

    def processes(self):
        matches = []
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    if os.readlink(entry / "exe").startswith(str(self.root) + "/"):
                        matches.append(int(entry.name))
                except OSError:
                    pass
        return matches

    def stop(self, force=False):
        if self.process:
            try:
                os.killpg(self.process.pid, signal.SIGKILL if force else signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
            eventually(self.processes, lambda p: not p, timeout=15)

    def preserved(self):
        assert [digest(self.config), digest(self.data)] == self.original
        for path in self.updates.rglob("*.json"):
            body = path.read_bytes()
            for secret in [SECRET, URL_SECRET, TOKEN]:
                assert secret.encode() not in body, (path.name, "secret in journal")
        for pid in self.processes():
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if cmd[1:2] == [b"--standalone-updater-server"]:
                cmd.pop(1)
            if cmd[1:2] == [b"--standalone-updater-worker"]:
                continue
            assert cmd[1:-1] == [a.encode() for a in self.arguments], cmd
            assert os.readlink(f"/proc/{pid}/cwd") == str(self.work)
            assert ("DEMO_SENTINEL_SECRET=" + SECRET).encode() + b"\0" in Path(f"/proc/{pid}/environ").read_bytes()

    def close(self):
        self.stop()
        self.log.close()
        self.install_dir.chmod(0o700)


def expect_http(code, action):
    try:
        action()
    except urllib.error.HTTPError as error:
        assert error.code == code, (error.code, error.read())
    else:
        raise AssertionError(f"expected HTTP {code}")


def run_cases(fixtures):
    report = []
    with tempfile.TemporaryDirectory(prefix="standalone-updater-e2e-") as temporary:
        root = Path(temporary)
        # The unprivileged scenario needs traversal of this root, not write access.
        root.chmod(0o755)
        keys = root / "test-keys"
        keys.mkdir(mode=0o700)
        source = Source(fixtures, keys)
        counter = 0

        def app(mode="supervisor", **options):
            nonlocal counter
            counter += 1
            return App(root / str(counter), fixtures, source, mode, **options)

        def passed(name):
            print("PASS:", name, flush=True)
            report.append(name)

        try:
            for mode in ["standalone", "supervisor"]:
                source.select()
                instance = app(mode)
                try:
                    original_pid = instance.process.pid
                    expect_http(401, lambda: instance.call("/update/check", {}, "POST", authorized=False))
                    expect_http(403, lambda: instance.call("/update/check", {}, "POST", headers={"Origin": "https://untrusted.invalid"}))
                    checked = instance.call("/update/check", {}, "POST")
                    selected = instance.wait_stage("available")["status"]
                    request = dict(check_id=checked["operation_id"], version=selected["available"]["version"])
                    expect_http(422, lambda: instance.call("/update/prepare", dict(request, url="https://untrusted.invalid"), "POST"))

                    def prepare_once():
                        try:
                            instance.call("/update/prepare", request, "POST")
                            return 202
                        except urllib.error.HTTPError as error:
                            return error.code

                    with concurrent.futures.ThreadPoolExecutor(2) as pool:
                        results = list(pool.map(lambda _: prepare_once(), range(2)))
                    assert sorted(results) == [202, 409], results
                    observed = []

                    def progress():
                        result = instance.status()
                        observed.append(result["status"]["downloaded_bytes"])
                        return result

                    eventually(progress, lambda r: r["status"]["state"] == "prepared")
                    expect_http(409, lambda: instance.call("/update/check", {}, "POST"))
                    assert source.downloads == 1
                    source.stop()
                    instance.install(checked["operation_id"])
                    completed = instance.wait_stage("completed")
                    assert completed["current_version"] == "0.6.0"
                    assert digest(instance.installed) == digest(fixtures / "good")
                    assert any(0 < n < completed["status"]["total_bytes"] for n in observed), observed
                    instance.preserved()
                    if mode == "supervisor":
                        assert instance.process.pid == original_pid and instance.process.poll() is None
                        assert digest(instance.binary) == digest(fixtures / "old")
                    else:
                        assert instance.process.wait(timeout=5) == 0
                    instance.stop()
                    instance.start()
                    assert instance.status()["current_version"] == "0.6.0"
                    assert instance.status()["status"]["state"] == "completed"
                    instance.preserved()
                    passed(f"{mode}: signed update, concurrent prepare, offline install, restart and byte-identical config/data")
                    if mode == "supervisor":
                        source.select("next")
                        operation = instance.prepare()
                        source.stop()
                        pid = instance.process.pid
                        instance.install(operation)
                        assert instance.wait_stage("completed")["current_version"] == "0.7.0"
                        assert instance.process.pid == pid
                        instance.stop(force=True)
                        instance.start()
                        assert instance.status()["current_version"] == "0.7.0"
                        passed("supervisor: consecutive updates and SIGKILL restart preserve active release")
                finally:
                    instance.close()

            for mode in ["standalone", "supervisor"]:
                for failure in ["fail-start", "fail-health"]:
                    source.select(failure)
                    instance = app(mode)
                    try:
                        operation = instance.prepare()
                        source.stop()
                        instance.install(operation)
                        result = instance.wait_stage("rolled_back")
                        assert result["current_version"] == "0.5.0"
                        assert digest(instance.installed) == digest(fixtures / "old")
                        instance.preserved()
                        passed(f"{mode}: rollback after {failure}")
                    finally:
                        instance.close()

            for mode in ["standalone", "supervisor"]:
                source.select("incompatible")
                instance = app(mode)
                try:
                    checked = instance.call("/update/check", {}, "POST")
                    instance.wait_stage("available")
                    instance.call("/update/prepare", dict(check_id=checked["operation_id"], version="0.6.0"), "POST")
                    failed = instance.wait_stage("failed")
                    assert "data compatibility" in failed["status"]["message"]
                    assert failed["current_version"] == "0.5.0" and instance.process.poll() is None
                    assert digest(instance.installed) == digest(fixtures / "old")
                    instance.preserved()
                    passed(f"{mode}: incompatible data is rejected before shutdown")
                finally:
                    instance.close()

            for mode in ["standalone", "supervisor"]:
                source.select(delay=0.025)
                instance = app(mode)
                try:
                    checked = instance.call("/update/check", {}, "POST")
                    instance.wait_stage("available")
                    instance.call("/update/prepare", dict(check_id=checked["operation_id"], version="0.6.0"), "POST")
                    eventually(instance.status, lambda r: r["status"]["state"] == "downloading" and 0 < r["status"]["downloaded_bytes"] < r["status"]["total_bytes"])
                    instance.stop(force=True)
                    source.stop()
                    instance.start()
                    failed = instance.wait_stage("failed")
                    assert not failed["status"]["recovery_required"]
                    assert not list((instance.updates / "staging").glob("*.part"))
                    assert digest(instance.installed) == digest(fixtures / "old")
                    instance.preserved()
                    passed(f"{mode}: SIGKILL during download reconciles safely offline")
                finally:
                    instance.close()

            source.select("fail-health")
            instance = app("supervisor")
            try:
                operation = instance.prepare()
                source.stop()
                instance.install(operation)
                eventually(instance.durable, lambda r: r["state"] == "health_check")
                instance.stop(force=True)
                instance.start()
                assert instance.wait_stage("rolled_back")["current_version"] == "0.5.0"
                instance.preserved()
                passed("supervisor: SIGKILL after switch automatically restores previous binary")
            finally:
                instance.close()

            source.select("fail-health")
            instance = app("standalone")
            try:
                operation = instance.prepare()
                source.stop()
                instance.install(operation)
                state = eventually(instance.durable, lambda r: r["state"] == "health_check")
                os.kill(state["worker"]["pid"], signal.SIGKILL)
                instance.stop()
                subprocess.run([instance.binary, "--standalone-updater-recover"], cwd=instance.work, env=instance.env, check=True, stdout=instance.log, stderr=instance.log)
                assert digest(instance.binary) == digest(fixtures / "old")
                instance.start()
                assert instance.wait_stage("rolled_back")["current_version"] == "0.5.0"
                instance.preserved()
                passed("standalone: killed worker supports offline explicit recovery")
            finally:
                instance.close()

            for mode, options in [("external", {}), ("standalone", {"readonly": True}), ("supervisor", {"manual_only": True})]:
                source.select()
                instance = app(mode, **options)
                try:
                    checked = instance.call("/update/check", {}, "POST")
                    instance.wait_stage("available")
                    assert not instance.status()["installation_supported"]
                    expect_http(409, lambda: instance.call("/update/prepare", dict(check_id=checked["operation_id"], version="0.6.0"), "POST"))
                    assert source.downloads == 0
                    assert digest(instance.binary) == digest(fixtures / "old")
                    instance.preserved()
                    passed(f"{mode}: check remains available when installation is forbidden")
                finally:
                    instance.close()

            for mode in ["standalone", "supervisor"]:
                source.select()
                instance = app(mode, initial="unclean-old")
                try:
                    operation = instance.prepare()
                    source.stop()
                    instance.install(operation)
                    instance.process.wait(timeout=15)
                    # EOF/nonzero exit without a clean-stop marker never approves
                    # replacement. A restart can reconcile the cancelled handoff.
                    eventually(instance.processes, lambda p: not p)
                    assert digest(instance.installed) == digest(fixtures / "unclean-old")
                    instance.start()
                    failed = instance.wait_stage("failed")
                    assert not failed["status"]["recovery_required"]
                    instance.preserved()
                    passed(f"{mode}: shutdown failure and EOF cannot approve a binary switch")
                finally:
                    instance.close()

            if Path("/limited").is_dir():
                source.select()
                instance = App(Path(tempfile.mkdtemp(dir="/limited", prefix="space-") ) / "app", fixtures, source, "standalone")
                try:
                    checked = instance.call("/update/check", {}, "POST")
                    instance.wait_stage("available")
                    instance.call("/update/prepare", dict(check_id=checked["operation_id"], version="0.6.0"), "POST")
                    failed = instance.wait_stage("failed")
                    assert "свободного места" in failed["status"]["message"], failed
                    assert source.downloads == 0 and instance.process.poll() is None
                    assert digest(instance.binary) == digest(fixtures / "old")
                    instance.preserved()
                    passed("standalone: real bounded tmpfs rejects insufficient space before download/shutdown")
                finally:
                    instance.close()
                    shutil.rmtree(instance.root.parent)

            if os.geteuid() == 0:
                source.select()
                instance = app("supervisor", unprivileged=True)
                try:
                    operation = instance.prepare()
                    source.stop()
                    instance.install(operation)
                    assert instance.wait_stage("completed")["current_version"] == "0.6.0"
                    assert digest(instance.binary) == digest(fixtures / "old")
                    assert instance.binary.stat().st_uid == 0
                    assert instance.installed.stat().st_uid == 65534
                    instance.preserved()
                    passed("supervisor: unprivileged process updates working copy of a root-owned read-only launcher")
                finally:
                    instance.close()
        except BaseException:
            print("Failure logs:", flush=True)
            for log in root.glob("*/process.log"):
                print(log.parent.name, log.read_text(errors="replace")[-5000:], flush=True)
            raise
        finally:
            source.stop()
    destination = ROOT / "target/validation"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "e2e.json").write_text(json.dumps(dict(platform=platform.platform(), scenarios=report), indent=2) + "\n")
    print(f"Passed {len(report)} process scenarios", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--run-only", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" and not args.native:
        command = ["docker", "run", "--rm", "--init", "--tmpfs", "/limited:rw,exec,size=32m,mode=0700", "-v", f"{ROOT}:/work", "-v", "standalone-updater-registry:/usr/local/cargo/registry", "-w", "/work", "-e", "CARGO_TARGET_DIR=/work/target/linux", "rust:1.91.1-bookworm", "python3", "scripts/e2e.py", "--native"]
        if args.run_only:
            command.append("--run-only")
        subprocess.run(command, check=True)
        return
    assert platform.system() == "Linux", "installation E2E requires Linux"
    fixtures = ROOT / "target/e2e-fixtures"
    if not args.run_only:
        build(fixtures)
    run_cases(fixtures)


if __name__ == "__main__":
    main()
