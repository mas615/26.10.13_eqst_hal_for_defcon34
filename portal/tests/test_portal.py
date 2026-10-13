import hashlib
import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PortalIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = cls.temp_dir.name
        os.environ["ADMIN_IP"] = "127.0.0.1"
        os.environ.pop("ADMIN_IPS", None)
        os.environ["PUBLIC_HOST"] = "ctf.example.test"
        os.environ["RATE_LIMIT_ATTEMPTS"] = "360"
        os.environ["CHALLENGES_FILE"] = str(
            Path(cls.temp_dir.name) / "missing-challenges.json"
        )
        os.environ["ATTACHMENTS_ROOT"] = str(PROJECT_ROOT.parent / "attachments")

        spec = importlib.util.spec_from_file_location(
            "halctf_portal_app",
            PROJECT_ROOT / "app.py",
        )
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

        cls.test_flag = "flag{portal_integration_test}"
        cls.original_orange_hash = cls.app.CHALLENGES_BY_ID["orange"]["flag_sha256"]
        cls.app.CHALLENGES_BY_ID["orange"]["flag_sha256"] = hashlib.sha256(
            cls.test_flag.encode("utf-8")
        ).hexdigest()

        cls.app.initialize_database()
        cls.server = cls.app.PortalServer(("127.0.0.1", 0), cls.app.PortalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.app.CHALLENGES_BY_ID["orange"][
            "flag_sha256"
        ] = cls.original_orange_hash
        cls.temp_dir.cleanup()

    def json_request(self, path, payload=None, headers=None):
        data = None
        request_headers = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=request_headers,
            method="POST" if payload is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, dict(response.headers), json.load(response)

    def test_health_manifest_submission_and_leaderboard(self):
        status, headers, health = self.json_request("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(self.app.RATE_LIMIT_ATTEMPTS, 360)

        _, _, manifest = self.json_request("/api/challenges")
        self.assertEqual(len(manifest["challenges"]), 5)
        self.assertNotIn("flag_sha256", json.dumps(manifest))

        _, _, wrong = self.json_request(
            "/api/submit",
            {
                "agent": "agent-test",
                "challenge": "orange",
                "flag": "flag{wrong}",
            },
        )
        self.assertFalse(wrong["correct"])

        _, _, correct = self.json_request(
            "/api/submit",
            {
                "agent": "agent-test",
                "challenge": "orange",
                "flag": self.test_flag,
            },
        )
        self.assertTrue(correct["correct"])
        self.assertTrue(correct["first_solve"])
        self.assertNotIn("source_ip", correct)

        _, _, repeat = self.json_request(
            "/api/submit",
            {
                "agent": "agent-test",
                "challenge": "orange",
                "flag": self.test_flag,
            },
        )
        self.assertTrue(repeat["correct"])
        self.assertFalse(repeat["first_solve"])

        _, _, overview = self.json_request(
            "/api/admin/overview",
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        self.assertEqual(overview["summary"]["unique_solves"], 1)
        self.assertEqual(overview["summary"]["agents"], 1)
        self.assertEqual(overview["leaderboard"][0]["agent_id"], "agent-test")
        self.assertEqual(overview["recent"][0]["submitted_value"], self.test_flag)
        self.assertNotIn("source_ip", json.dumps(overview))

        for agent_id in ("agent-second", "agent-third", "agent-fourth"):
            _, _, extra_solve = self.json_request(
                "/api/submit",
                {
                    "agent": agent_id,
                    "challenge": "orange",
                    "flag": self.test_flag,
                },
            )
            self.assertTrue(extra_solve["correct"])
            self.assertTrue(extra_solve["first_solve"])

        _, _, public_board = self.json_request("/api/leaderboard")
        agent_test = next(
            row
            for row in public_board["leaderboard"]
            if row["agent_id"] == "agent-test"
        )
        solved_challenges = agent_test["solved_challenges"]
        self.assertEqual(len(solved_challenges), 1)
        self.assertEqual(
            set(solved_challenges[0]),
            {
                "challenge_id",
                "name",
                "category",
                "points",
                "first_solved_at",
            },
        )
        self.assertEqual(solved_challenges[0]["challenge_id"], "orange")
        self.assertEqual(
            solved_challenges[0]["name"],
            self.app.CHALLENGES_BY_ID["orange"]["name"],
        )
        self.assertEqual(len(public_board["challenge_first_bloods"]), 5)
        orange_first_bloods = next(
            row
            for row in public_board["challenge_first_bloods"]
            if row["challenge_id"] == "orange"
        )
        self.assertEqual(
            set(orange_first_bloods),
            {"challenge_id", "name", "category", "points", "solvers"},
        )
        self.assertEqual(
            [solver["agent_id"] for solver in orange_first_bloods["solvers"]],
            ["agent-test", "agent-second", "agent-third"],
        )
        self.assertEqual(
            [solver["rank"] for solver in orange_first_bloods["solvers"]],
            [1, 2, 3],
        )
        self.assertTrue(
            all(
                set(solver) == {"rank", "agent_id", "first_solved_at"}
                for solver in orange_first_bloods["solvers"]
            )
        )
        self.assertNotIn(
            "agent-fourth",
            [solver["agent_id"] for solver in orange_first_bloods["solvers"]],
        )
        self.assertTrue(
            all(
                len(challenge["solvers"]) <= 3
                for challenge in public_board["challenge_first_bloods"]
            )
        )
        self.assertEqual(len(public_board["recent_submissions"]), 6)
        self.assertEqual(
            set(public_board["recent_submissions"][0]),
            {"created_at", "agent_id", "challenge_id", "correct"},
        )
        self.assertNotIn("source_ip", json.dumps(public_board))
        self.assertNotIn("submitted_value", json.dumps(public_board))
        self.assertNotIn(self.test_flag, json.dumps(public_board))

        with closing(sqlite3.connect(self.app.DB_PATH)) as connection:
            rows = connection.execute(
                "SELECT candidate_sha256, candidate_text FROM submissions"
            ).fetchall()
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(len(row[0]) == 64 for row in rows))
        self.assertEqual(
            [row[1] for row in rows],
            [
                "flag{wrong}",
                self.test_flag,
                self.test_flag,
                self.test_flag,
                self.test_flag,
                self.test_flag,
            ],
        )

    def test_admin_rejects_non_allowlisted_socket_ip(self):
        original_admin_ip = self.app.ADMIN_IP
        self.app.ADMIN_IP = "192.0.2.10"
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.json_request(
                    "/api/admin/overview",
                    headers={"X-Forwarded-For": "192.0.2.10"},
                )
            self.assertEqual(raised.exception.code, 403)
        finally:
            self.app.ADMIN_IP = original_admin_ip

    def test_legacy_database_adds_candidate_text_column(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    correct INTEGER NOT NULL CHECK (correct IN (0, 1)),
                    user_agent TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                INSERT INTO submissions (
                    created_at, source_ip, agent_id, challenge_id,
                    candidate_sha256, correct, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-07-30T00:00:00Z",
                    "127.0.0.1",
                    "legacy-agent",
                    "orange",
                    "0" * 64,
                    0,
                    "",
                ),
            )

        original_db_path = self.app.DB_PATH
        self.app.DB_PATH = legacy_path
        try:
            self.app.initialize_database()
            with closing(sqlite3.connect(legacy_path)) as connection:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(submissions)"
                    )
                }
                legacy_value = connection.execute(
                    "SELECT candidate_text FROM submissions"
                ).fetchone()[0]
            self.assertIn("candidate_text", columns)
            self.assertIsNone(legacy_value)
        finally:
            self.app.DB_PATH = original_db_path

    def test_attachment_download_is_exact(self):
        with urllib.request.urlopen(
            self.base_url + "/files/bigboi/boi",
            timeout=3,
        ) as response:
            downloaded = response.read()
        source = (self.app.ATTACHMENTS_ROOT / "bigboi" / "boi").read_bytes()
        self.assertEqual(hashlib.sha256(downloaded).digest(), hashlib.sha256(source).digest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
