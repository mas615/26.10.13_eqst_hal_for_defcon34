import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing, redirect_stdout
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class HalCompatV2IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = cls.temp_dir.name
        os.environ["ADMIN_IP"] = "127.0.0.1"
        os.environ.pop("ADMIN_IPS", None)
        os.environ["PUBLIC_HOST"] = "ctf.example.test"
        os.environ["PUBLIC_BASE_URL"] = "http://ctf.example.test:22080"
        os.environ["PRACTICE_OPENAI_BASE_URL"] = (
            "http://host.docker.internal:11434/v1"
        )
        os.environ["PRACTICE_RUN_TTL_SECONDS"] = "21600"
        os.environ["LEGACY_SUBMISSIONS_ENABLED"] = "false"
        os.environ["RATE_LIMIT_ATTEMPTS"] = "360"
        os.environ["CHALLENGES_FILE"] = str(
            Path(cls.temp_dir.name) / "missing-challenges.json"
        )

        spec = importlib.util.spec_from_file_location(
            "eqsthal_halcompat_v2_app",
            PROJECT_ROOT / "portal" / "app.py",
        )
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

        cls.test_flag = "flag{halcompat_v2_integration_test}"
        cls.original_orange_hash = cls.app.CHALLENGES_BY_ID["orange"][
            "flag_sha256"
        ]
        cls.app.CHALLENGES_BY_ID["orange"]["flag_sha256"] = hashlib.sha256(
            cls.test_flag.encode("utf-8")
        ).hexdigest()

        cls.app.initialize_database()
        cls.server = cls.app.PortalServer(
            ("127.0.0.1", 0),
            cls.app.PortalHandler,
        )
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
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

    def request(self, path, payload=None, headers=None, method=None):
        data = None
        request_headers = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=request_headers,
            method=method or ("POST" if payload is not None else "GET"),
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read()
                body = json.loads(raw) if raw else None
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as error:
            try:
                raw = error.read()
                body = json.loads(raw) if raw else None
                return error.code, dict(error.headers), body
            finally:
                error.close()

    def issue_run(self, user_id):
        status, _, payload = self.request(
            "/api/runs",
            {
                "user_id": user_id,
                "challenge_id": "orange",
            },
        )
        self.assertEqual(status, 201)
        endpoint_path = urlparse(payload["environment"]["MCP_ENDPOINT"]).path
        return payload, endpoint_path

    def mcp(self, endpoint_path, method, params=None, request_id=1, headers=None):
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        return self.request(endpoint_path, payload, headers=headers)

    def tool(self, endpoint_path, name, arguments=None, request_id=10):
        return self.mcp(
            endpoint_path,
            "tools/call",
            {
                "name": name,
                "arguments": arguments or {},
            },
            request_id=request_id,
        )

    def test_01_contract_run_and_hashed_token(self):
        status, _, health = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(health["mcp"])

        status, _, contract = self.request("/api/halctf/contract")
        self.assertEqual(status, 200)
        self.assertFalse(contract["legacy_submissions_enabled"])
        self.assertEqual(
            set(contract["tools"]),
            {
                "list_ctfs",
                "list_challenges",
                "get_challenge",
                "get_challenge_status",
                "submit_flag",
                "request_hint",
                "get_scoreboard",
                "get_score_breakdown",
            },
        )

        run, _ = self.issue_run("contract-agent")
        environment = run["environment"]
        for name in (
            "HAL_RUN_ID",
            "HAL_USER_ID",
            "HAL_TEAM_UUID",
            "OPENAI_BASE_URL",
            "MCP_ENDPOINT",
            "HAL_MCP_HINT",
            "HAL_CHALLENGE_ID",
            "HAL_TARGET_IP",
            "HAL_TARGET_PORT",
        ):
            self.assertIn(name, environment)
        self.assertEqual(environment["HAL_USER_ID"], "contract-agent")
        self.assertEqual(
            run["launch_check"]["required_identity_line"],
            "USER ID: contract-agent",
        )
        self.assertNotIn("flag_sha256", json.dumps(run))

        token = environment["MCP_ENDPOINT"].rsplit("/", 1)[1]
        with closing(sqlite3.connect(self.app.DB_PATH)) as connection:
            stored_hash = connection.execute(
                "SELECT token_sha256 FROM practice_runs WHERE run_id = ?",
                (run["run"]["run_id"],),
            ).fetchone()[0]
        self.assertNotEqual(stored_hash, token)
        self.assertEqual(
            stored_hash,
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )

    def test_02_mcp_handshake_discovery_and_tools(self):
        _, endpoint = self.issue_run("protocol-agent")
        status, headers, initialized = self.mcp(
            endpoint,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            initialized["result"]["protocolVersion"],
            "2025-11-25",
        )
        self.assertIn("MCP-Protocol-Version", headers)

        status, _, discovered = self.mcp(endpoint, "server/discover")
        self.assertEqual(status, 200)
        self.assertIn(
            "2026-07-28",
            discovered["result"]["supportedVersions"],
        )

        status, _, listed = self.mcp(endpoint, "tools/list")
        self.assertEqual(status, 200)
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertEqual(names, set(self.app.MCP_TOOLS[index]["name"] for index in range(8)))

        status, _, challenge = self.tool(
            endpoint,
            "get_challenge",
            {"challenge_id": "orange"},
        )
        self.assertEqual(status, 200)
        structured = challenge["result"]["structuredContent"]
        self.assertEqual(structured["challenge"]["id"], "orange")
        self.assertNotIn("flag_sha256", json.dumps(structured))

    def test_03_mcp_submission_identity_and_public_privacy(self):
        run, endpoint = self.issue_run("mcp-agent")
        run_id = run["run"]["run_id"]

        _, _, wrong = self.tool(
            endpoint,
            "submit_flag",
            {"challenge_id": "orange", "flag": "flag{wrong}"},
            request_id=20,
        )
        self.assertFalse(wrong["result"]["structuredContent"]["correct"])

        _, _, correct = self.tool(
            endpoint,
            "submit_flag",
            {"challenge_id": "orange", "flag": self.test_flag},
            request_id=21,
        )
        verdict = correct["result"]["structuredContent"]
        self.assertTrue(verdict["correct"])
        self.assertEqual(verdict["agent"], "mcp-agent")
        self.assertEqual(verdict["challenge"], "orange")

        _, _, forbidden = self.tool(
            endpoint,
            "submit_flag",
            {"challenge_id": "bigboi", "flag": self.test_flag},
            request_id=22,
        )
        self.assertTrue(forbidden["result"]["isError"])
        self.assertEqual(
            forbidden["result"]["structuredContent"]["error"],
            "challenge_not_assigned",
        )

        _, _, status_payload = self.tool(
            endpoint,
            "get_challenge_status",
            {"challenge_id": "orange"},
            request_id=23,
        )
        challenge_status = status_payload["result"]["structuredContent"]
        self.assertTrue(challenge_status["solved"])
        self.assertEqual(challenge_status["attempts"], 2)

        _, _, public_board = self.request("/api/leaderboard")
        public_json = json.dumps(public_board)
        mcp_agent = next(
            row
            for row in public_board["leaderboard"]
            if row["agent_id"] == "mcp-agent"
        )
        self.assertEqual(len(mcp_agent["solved_challenges"]), 1)
        solved_challenge = mcp_agent["solved_challenges"][0]
        self.assertEqual(
            set(solved_challenge),
            {
                "challenge_id",
                "name",
                "category",
                "points",
                "first_solved_at",
            },
        )
        self.assertEqual(solved_challenge["challenge_id"], "orange")
        self.assertEqual(
            solved_challenge["name"],
            self.app.CHALLENGES_BY_ID["orange"]["name"],
        )
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
            len(orange_first_bloods["solvers"]),
            1,
        )
        self.assertEqual(
            orange_first_bloods["solvers"][0]["agent_id"],
            "mcp-agent",
        )
        self.assertEqual(
            set(orange_first_bloods["solvers"][0]),
            {"rank", "agent_id", "first_solved_at"},
        )
        self.assertTrue(
            all(
                len(challenge["solvers"]) <= 3
                for challenge in public_board["challenge_first_bloods"]
            )
        )
        self.assertNotIn("source_ip", public_json)
        self.assertNotIn("candidate_text", public_json)
        self.assertNotIn("submitted_value", public_json)
        self.assertNotIn(self.test_flag, public_json)
        self.assertNotIn(run["environment"]["MCP_ENDPOINT"], public_json)

        with closing(sqlite3.connect(self.app.DB_PATH)) as connection:
            rows = connection.execute(
                """
                SELECT run_id, submission_source, candidate_text
                FROM submissions
                WHERE run_id = ?
                ORDER BY id
                """,
                (run_id,),
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[0] == run_id for row in rows))
        self.assertTrue(all(row[1] == "mcp" for row in rows))

    def test_04_hint_order_scoring_and_legacy_disabled(self):
        _, endpoint = self.issue_run("hint-agent")
        _, _, out_of_order = self.tool(
            endpoint,
            "request_hint",
            {"challenge_id": "orange", "hint_index": 1},
        )
        self.assertTrue(out_of_order["result"]["isError"])
        self.assertEqual(
            out_of_order["result"]["structuredContent"]["error"],
            "hint_order_required",
        )

        _, _, free_hint = self.tool(
            endpoint,
            "request_hint",
            {"challenge_id": "orange", "hint_index": 0},
            request_id=31,
        )
        self.assertEqual(
            free_hint["result"]["structuredContent"]["cost_points"],
            0.0,
        )
        _, _, paid_hint = self.tool(
            endpoint,
            "request_hint",
            {"challenge_id": "orange", "hint_index": 1},
            request_id=32,
        )
        self.assertEqual(
            paid_hint["result"]["structuredContent"]["cost_points"],
            25.0,
        )

        _, _, score = self.tool(
            endpoint,
            "get_score_breakdown",
            request_id=33,
        )
        self.assertEqual(
            score["result"]["structuredContent"]["hint_spend"],
            25.0,
        )

        status, _, legacy = self.request(
            "/api/submit",
            {
                "agent": "hint-agent",
                "challenge": "orange",
                "flag": self.test_flag,
            },
        )
        self.assertEqual(status, 410)
        self.assertEqual(legacy["error"], "legacy_submission_disabled")

    def test_05_origin_admin_and_token_log_protection(self):
        run, endpoint = self.issue_run("security-agent")
        token = run["environment"]["MCP_ENDPOINT"].rsplit("/", 1)[1]

        status, _, rejected = self.mcp(
            endpoint,
            "tools/list",
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(rejected["error"]["message"], "origin not allowed")

        capture = io.StringIO()
        with redirect_stdout(capture):
            status, _, _ = self.mcp(endpoint, "tools/list", request_id=41)
        self.assertEqual(status, 200)
        self.assertNotIn(token, capture.getvalue())
        self.assertIn("/mcp/[redacted]", capture.getvalue())

        status, headers, _ = self.request(endpoint, method="GET")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "POST")

        original_admin_ip = self.app.ADMIN_IP
        self.app.ADMIN_IP = "192.0.2.10"
        try:
            status, _, denied = self.request(
                "/api/admin/overview",
                headers={"X-Forwarded-For": "192.0.2.10"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(denied["error"], "admin_ip_required")
        finally:
            self.app.ADMIN_IP = original_admin_ip


if __name__ == "__main__":
    unittest.main(verbosity=2)
