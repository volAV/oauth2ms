"""Offline regression checks; no Microsoft requests or personal credentials."""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlencode


SCRIPT = Path(__file__).resolve().parents[1] / "oauth2ms"
loader = importlib.machinery.SourceFileLoader("oauth2ms_app", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
oauth = importlib.util.module_from_spec(spec)
loader.exec_module(oauth)


def stop_agent(home):
    subprocess.run(
        ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
        capture_output=True,
    )


class CallbackTest(unittest.TestCase):
    def request(self, app, query, path="/getToken", method="GET"):
        statuses = []
        app({"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query},
            lambda status, headers: statuses.append(status))
        return statuses[0].split()[0]

    def test_unrelated_or_invalid_requests_do_not_complete_authorization(self):
        app = oauth.WSGIRedirectionApp("/getToken", "expected-state")
        valid = urlencode({"state": "expected-state", "code": "fixture-code"})
        invalid = [
            ("state=wrong&code=fixture", "/getToken", "GET"),
            ("state=%D1%8F&code=fixture", "/getToken", "GET"),
            ("code=fixture", "/getToken", "GET"),
            (valid, "/favicon.ico", "GET"),
            (valid, "/getToken", "POST"),
            (valid + "&state=wrong", "/getToken", "GET"),
            (valid + "&code=another", "/getToken", "GET"),
            (valid + "&error=access_denied", "/getToken", "GET"),
            ("state=expected-state&code=", "/getToken", "GET"),
        ]
        for query, path, method in invalid:
            with self.subTest(query=query, path=path, method=method):
                self.assertNotEqual(self.request(app, query, path, method), "200")
                self.assertIsNone(app.auth_response)
        self.assertEqual(self.request(app, valid), "200")
        self.assertEqual(app.auth_response,
                         {"state": "expected-state", "code": "fixture-code"})

    def test_matching_authorization_denial_finishes_waiting(self):
        app = oauth.WSGIRedirectionApp("/", "expected-state")
        status = self.request(
            app, "state=expected-state&error=access_denied", path="/")
        self.assertEqual(status, "200")
        self.assertEqual(app.auth_response["error"], "access_denied")


class PersistenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="oauth2ms-test-keys-")
        cls.addClassCleanup(cls.keys.cleanup)
        cls.gpg_home = Path(cls.keys.name)
        cls.gpg_home.chmod(0o700)
        cls.addClassCleanup(stop_agent, cls.gpg_home)
        subprocess.run([
            "gpg", "--homedir", str(cls.gpg_home), "--batch", "--pinentry-mode",
            "loopback", "--passphrase", "", "--quick-generate-key",
            "OAuth Test Fixture <fixture@example.invalid>", "rsa2048", "encr", "0",
        ], capture_output=True, check=True)
        cls.gpg = oauth.gnupg.GPG(gnupghome=str(cls.gpg_home))
        cls.fingerprint = cls.gpg.list_keys()[0]["fingerprint"]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oauth2ms-test-cache-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.filename = self.root / "credentials.bin"
        self.cache = oauth.msal.SerializableTokenCache()
        self.cache.has_state_changed = True
        self.app = {
            "config": {"tenant_id": "fixture-tenant", "client_id": "fixture-client",
                       "client_secret": "fixture-secret", "scopes": ["fixture-scope"]},
            "cache": self.cache,
            "crypt": {"gpg": self.gpg, "fingerprint": self.fingerprint},
        }

    def test_encrypted_cache_is_decryptable_and_owner_only(self):
        previous = os.umask(0)
        try:
            oauth.save_credentials(self.app, str(self.filename))
        finally:
            os.umask(previous)
        ciphertext = self.filename.read_bytes()
        self.assertNotIn(b"fixture-secret", ciphertext)
        decrypted = self.gpg.decrypt(ciphertext)
        self.assertTrue(decrypted.ok)
        self.assertEqual(json.loads(str(decrypted))["client_secret"], "fixture-secret")
        self.assertEqual(self.filename.stat().st_mode & 0o777, 0o600)

    def test_unusable_recipient_preserves_previous_cache(self):
        oauth.save_credentials(self.app, str(self.filename))
        previous = self.filename.read_bytes()
        self.app["crypt"] = {"gpg": self.gpg, "fingerprint": "F" * 40}
        with self.assertRaises(RuntimeError):
            oauth.save_credentials(self.app, str(self.filename))
        self.assertEqual(self.filename.read_bytes(), previous)
        self.assertEqual(list(self.root.glob(".credentials-*")), [])

    def test_failed_replace_preserves_previous_cache_and_removes_temporary(self):
        oauth.save_credentials(self.app, str(self.filename))
        previous = self.filename.read_bytes()
        with mock.patch.object(oauth.os, "replace", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                oauth.save_credentials(self.app, str(self.filename))
        self.assertEqual(self.filename.read_bytes(), previous)
        self.assertEqual(list(self.root.glob(".credentials-*")), [])

    def test_decryption_failure_does_not_replace_or_reauthorize(self):
        oauth.save_credentials(self.app, str(self.filename))
        previous = self.filename.read_bytes()
        empty_home = self.root / "empty-keyring"
        empty_home.mkdir(mode=0o700)
        self.addCleanup(stop_agent, empty_home)
        crypt = {"gpg": oauth.gnupg.GPG(gnupghome=str(empty_home)),
                 "fingerprint": "F" * 40}
        with self.assertRaises(RuntimeError):
            oauth.build_app_state_from_credentials(crypt, str(self.filename))
        self.assertEqual(self.filename.read_bytes(), previous)

    def test_cli_encryption_failure_emits_no_token_and_preserves_cache(self):
        oauth.save_credentials(self.app, str(self.filename))
        previous = self.filename.read_bytes()
        def refresh(app):
            app["cache"].has_state_changed = True
            return "fixture-access-token"
        stdout, stderr = io.StringIO(), io.StringIO()
        previous_umask = os.umask(0o077)
        try:
            with mock.patch.object(sys, "argv", [str(SCRIPT), "-e", "F" * 40,
                                                 "--gpg-home", str(self.gpg_home)]), \
                    mock.patch.object(oauth, "save_data_path", return_value=str(self.root)), \
                    mock.patch.object(oauth, "fetch_token_from_cache", side_effect=refresh), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = oauth.main()
        finally:
            os.umask(previous_umask)
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("fixture-access-token", stderr.getvalue())
        self.assertNotIn("fixture-secret", stderr.getvalue())
        self.assertEqual(self.filename.read_bytes(), previous)

    def test_empty_encryption_recipient_cannot_fall_back_to_plaintext(self):
        oauth.save_credentials(self.app, str(self.filename))
        previous = self.filename.read_bytes()
        with mock.patch.object(sys, "argv", [str(SCRIPT), "-e", ""]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                oauth.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.filename.read_bytes(), previous)


class ConcurrentRefreshTest(unittest.TestCase):
    def test_two_processes_refresh_from_latest_cache_without_overlap(self):
        with tempfile.TemporaryDirectory(prefix="oauth2ms-concurrency-") as tmp:
            root = Path(tmp)
            data = root / "data/oauth2ms"
            data.mkdir(parents=True)
            filename = data / "credentials.bin"
            filename.write_text(json.dumps({"counter": 0, "token_cache": "{}"}))
            filename.chmod(0o664)
            harness = root / "refresh.py"
            harness.write_text('''import importlib.machinery, importlib.util
import os, sys, time
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("oauth2ms_app", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
app = importlib.util.module_from_spec(spec)
loader.exec_module(app)
root = Path(sys.argv[2])
(root / ("ready-" + sys.argv[3])).touch()
deadline = time.monotonic() + 20
while len(list(root.glob("ready-*"))) != 2:
    if time.monotonic() > deadline:
        raise RuntimeError("fixture startup barrier timed out")
    time.sleep(0.01)
def refresh(state):
    counter = state["config"]["counter"]
    fd = os.open(root / "refresh-active", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        time.sleep(0.15)
        state["config"]["counter"] = counter + 1
        state["cache"].has_state_changed = True
    finally:
        os.close(fd)
        (root / "refresh-active").unlink()
    return "fixture-access-token"
app.fetch_token_from_cache = refresh
sys.argv = [sys.argv[1]]
sys.exit(app.main())
''')
            env = {**os.environ, "XDG_DATA_HOME": str(root / "data")}
            processes = [subprocess.Popen(
                [sys.executable, "-B", str(harness), str(SCRIPT), str(root), str(i)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) for i in range(2)]
            try:
                for process in processes:
                    stdout, stderr = process.communicate(timeout=30)
                    self.assertEqual(process.returncode, 0, stderr)
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
            self.assertEqual(json.loads(filename.read_text())["counter"], 2)
            self.assertEqual(filename.stat().st_mode & 0o777, 0o600)
            self.assertEqual((data / "credentials.bin.lock").stat().st_mode & 0o777, 0o600)
            self.assertEqual(data.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
