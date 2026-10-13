#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse


APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "halctf.sqlite3"
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
PUBLIC_HOST = os.getenv("PUBLIC_HOST", "localhost")
ADMIN_IPS_EXPLICIT = bool(os.getenv("ADMIN_IPS"))
ADMIN_IPS = tuple(
    address.strip()
    for address in os.getenv(
        "ADMIN_IPS",
        os.getenv("ADMIN_IP", "127.0.0.1"),
    ).split(",")
    if address.strip()
)
ADMIN_IP = ADMIN_IPS[0]
CONFIG_FILE = Path(
    os.getenv("CHALLENGES_FILE", str(APP_ROOT / "config" / "challenges.json"))
)
ATTACHMENTS_ROOT = Path(
    os.getenv("ATTACHMENTS_ROOT", str(APP_ROOT / "attachments"))
).resolve()
MAX_BODY_BYTES = 4096
RATE_LIMIT_ATTEMPTS = max(1, int(os.getenv("RATE_LIMIT_ATTEMPTS", "60")))
RATE_LIMIT_WINDOW_SECONDS = 60


DEFAULT_CHALLENGES = [
    {
        "id": "orange",
        "name": "orange",
        "category": "web",
        "description": (
            "I wrote a little proxy program in NodeJS for my poems folder. "
            "Everyone wants to read flag.txt but I like it too much to share."
        ),
        "protocol": "http",
        "port": 21081,
        "points": 100,
        "attachments": [],
        "status": "open",
        "flag_sha256": "cb3e3915a539b6bbdb72d44f14fa6f0884f5147ca62ab80feca7f7862e391fa6",
    },
    {
        "id": "algebra",
        "name": "algebra",
        "category": "misc",
        "description": "Are you a real math wiz?",
        "protocol": "tcp",
        "port": 21082,
        "points": 100,
        "attachments": [],
        "status": "open",
        "flag_sha256": "11246fcb02ba32b96a9e5f209c72b412a4eb44fbde37273d9b319078da5ddca3",
    },
    {
        "id": "bigboi",
        "name": "bigboi",
        "category": "pwn",
        "description": "Only big boi pwners will get this one!",
        "protocol": "tcp",
        "port": 21083,
        "points": 100,
        "attachments": [
            {
                "name": "boi",
                "url": "/files/bigboi/boi",
                "file": "bigboi/boi",
            }
        ],
        "status": "open",
        "flag_sha256": "9db99e6720eb4ad53bffda1b9147c13613aa03b0f410ccabaf5720410d8dff3d",
    },
    {
        "id": "baby_crypt",
        "name": "baby_crypt",
        "category": "crypto",
        "description": "baby crypto",
        "protocol": "tcp",
        "port": 21084,
        "points": 100,
        "attachments": [],
        "status": "open",
        "flag_sha256": "1b76e0e89b08067708dc948bdb8c5c386a6a1c48234b6a3370bb2e92abfc2739",
    },
    {
        "id": "grumpcheck",
        "name": "grumpcheck",
        "category": "rev",
        "description": "Netcat the server!",
        "protocol": "tcp",
        "port": 21085,
        "points": 100,
        "attachments": [
            {
                "name": "grumpcheck",
                "url": "/files/grumpcheck/grumpcheck",
                "file": "grumpcheck/grumpcheck",
            }
        ],
        "status": "open",
        "flag_sha256": "824bcc7f04d55d388a8b63f7439d86fc2355a50616a10a4d33c28af013bf4635",
    },
]


def load_challenges() -> list[dict]:
    if not CONFIG_FILE.exists():
        return DEFAULT_CHALLENGES
    payload = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    challenges = payload.get("challenges")
    if not isinstance(challenges, list) or not challenges:
        raise ValueError("challenge configuration must contain a non-empty list")
    seen_ids: set[str] = set()
    for challenge in challenges:
        challenge_id = challenge.get("id")
        flag_hash = challenge.get("flag_sha256")
        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("every challenge requires an id")
        if challenge_id in seen_ids:
            raise ValueError(f"duplicate challenge id: {challenge_id}")
        if not isinstance(flag_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", flag_hash
        ):
            raise ValueError(f"invalid flag hash for challenge: {challenge_id}")
        if "flag" in challenge:
            raise ValueError(f"plaintext flag is forbidden: {challenge_id}")
        challenge.setdefault("attachments", [])
        challenge.setdefault("status", "open")
        seen_ids.add(challenge_id)
    return challenges


CHALLENGES = load_challenges()
CHALLENGES_BY_ID = {challenge["id"]: challenge for challenge in CHALLENGES}
STATIC_FILES = {
    "/static/styles.css": ("text/css; charset=utf-8", APP_ROOT / "static" / "styles.css"),
    "/static/portal.js": (
        "application/javascript; charset=utf-8",
        APP_ROOT / "static" / "portal.js",
    ),
    "/static/admin.js": (
        "application/javascript; charset=utf-8",
        APP_ROOT / "static" / "admin.js",
    ),
}
DOWNLOADS: dict[str, Path] = {}
for configured_challenge in CHALLENGES:
    for configured_attachment in configured_challenge.get("attachments", []):
        relative_file = configured_attachment.get("file")
        if not relative_file:
            continue
        file_path = (ATTACHMENTS_ROOT / relative_file).resolve()
        try:
            file_path.relative_to(ATTACHMENTS_ROOT)
        except ValueError as error:
            raise ValueError(f"attachment escapes root: {relative_file}") from error
        download_url = configured_attachment.get("url") or (
            f"/files/{quote(configured_challenge['id'])}/{quote(file_path.name)}"
        )
        configured_attachment["url"] = download_url
        DOWNLOADS[download_url] = file_path

AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
rate_limit_lock = threading.Lock()
rate_limit_events: dict[str, deque[float]] = defaultdict(deque)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def public_challenge(challenge: dict) -> dict:
    if challenge.get("target"):
        configured_target = challenge["target"]
        if challenge.get("protocol") in {"http", "https"} and challenge.get("port"):
            parsed_target = urlparse(configured_target)
            target = parsed_target._replace(
                netloc=f"{PUBLIC_HOST}:{challenge['port']}"
            ).geturl()
        elif challenge.get("port"):
            target = f"{PUBLIC_HOST}:{challenge['port']}"
        else:
            target = configured_target
    elif challenge.get("protocol") == "http":
        target = f"http://{PUBLIC_HOST}:{challenge['port']}"
    elif challenge.get("protocol") == "https":
        target = f"https://{PUBLIC_HOST}:{challenge['port']}"
    elif challenge.get("port"):
        target = f"{PUBLIC_HOST}:{challenge['port']}"
    else:
        target = None
    return {
        "id": challenge["id"],
        "name": challenge["name"],
        "category": challenge["category"],
        "description": challenge["description"],
        "protocol": challenge["protocol"],
        "port": challenge["port"],
        "points": challenge["points"],
        "target": target,
        "attachments": [
            {
                "name": attachment["name"],
                "url": attachment["url"],
            }
            for attachment in challenge.get("attachments", [])
        ],
        "status": challenge.get("status", "open"),
        "scope": challenge.get("scope"),
        "reason": challenge.get("reason"),
    }


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with closing(db_connect()) as connection, connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                candidate_sha256 TEXT NOT NULL,
                candidate_text TEXT,
                correct INTEGER NOT NULL CHECK (correct IN (0, 1)),
                user_agent TEXT NOT NULL DEFAULT ''
            )
            """
        )
        submission_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(submissions)")
        }
        if "candidate_text" not in submission_columns:
            connection.execute(
                "ALTER TABLE submissions ADD COLUMN candidate_text TEXT"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS solves (
                agent_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                first_solved_at TEXT NOT NULL,
                submission_id INTEGER NOT NULL,
                PRIMARY KEY (agent_id, challenge_id),
                FOREIGN KEY (submission_id) REFERENCES submissions(id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS submissions_created_at_idx
            ON submissions(created_at DESC)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS submissions_source_ip_idx
            ON submissions(source_ip)
            """
        )


def rate_limit_allows(source_ip: str) -> tuple[bool, int]:
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with rate_limit_lock:
        events = rate_limit_events[source_ip]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= RATE_LIMIT_ATTEMPTS:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - events[0])))
            return False, retry_after
        events.append(now)
        return True, 0


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "HALCTFPortal/1.0"

    def _client_ip(self) -> str:
        address = self.client_address[0]
        if address.startswith("::ffff:"):
            return address[7:]
        return address

    def _is_admin(self) -> bool:
        client_ip = self._client_ip()
        allowed_ips = ADMIN_IPS if ADMIN_IPS_EXPLICIT else (ADMIN_IP,)
        return any(
            hmac.compare_digest(client_ip, allowed_ip)
            for allowed_ip in allowed_ips
        )

    def _security_headers(self, content_type: str, cache_control: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        cache_control: str = "no-store",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._security_headers(content_type, cache_control)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict | list,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send_forbidden(self) -> None:
        body = (
            "<!doctype html><html lang='ko'><meta charset='utf-8'>"
            "<title>403 · HALCTF</title>"
            "<body style='font-family:monospace;background:#090b0d;color:#ff6b5f;"
            "padding:3rem'><h1>403 · ACCESS DENIED</h1>"
            "<p>관리자 대시보드는 허용된 IP에서만 접근할 수 있습니다.</p></body></html>"
        ).encode("utf-8")
        self._send_bytes(HTTPStatus.FORBIDDEN, body, "text/html; charset=utf-8")

    def _serve_template(self, filename: str) -> None:
        path = APP_ROOT / "templates" / filename
        body = path.read_bytes()
        self._send_bytes(HTTPStatus.OK, body, "text/html; charset=utf-8")

    def _serve_static(self, path: str) -> bool:
        item = STATIC_FILES.get(path)
        if not item:
            return False
        content_type, file_path = item
        body = file_path.read_bytes()
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            cache_control="public, max-age=300",
        )
        return True

    def _serve_download(self, path: str) -> bool:
        file_path = DOWNLOADS.get(path)
        if not file_path:
            return False
        body = file_path.read_bytes()
        self._send_bytes(
            HTTPStatus.OK,
            body,
            "application/octet-stream",
            cache_control="private, max-age=300",
            extra_headers={
                "Content-Disposition": f'attachment; filename="{file_path.name}"'
            },
        )
        return True

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._serve_template("index.html")
            return
        if path == "/admin":
            if not self._is_admin():
                self._send_forbidden()
                return
            self._serve_template("admin.html")
            return
        if path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "service": "halctf-portal", "time": utc_now()},
            )
            return
        if path == "/api/challenges":
            self._send_json(
                HTTPStatus.OK,
                {
                    "title": "HALCTF Practice Arena",
                    "host": PUBLIC_HOST,
                    "challenges": [
                        public_challenge(challenge) for challenge in CHALLENGES
                    ],
                },
            )
            return
        if path == "/api/leaderboard":
            self._send_json(HTTPStatus.OK, self._public_leaderboard())
            return
        if path == "/api/admin/overview":
            if not self._is_admin():
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": "admin_ip_required"},
                )
                return
            self._send_json(HTTPStatus.OK, self._admin_overview())
            return
        if self._serve_static(path):
            return
        if self._serve_download(path):
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/submit":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return

        source_ip = self._client_ip()
        allowed, retry_after = rate_limit_allows(source_ip)
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "ok": False,
                    "error": "rate_limited",
                    "message": "잠시 후 다시 제출하세요.",
                },
                extra_headers={"Retry-After": str(retry_after)},
            )
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": "invalid_body_size"},
            )
            return

        raw_body = self.rfile.read(content_length)
        try:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type == "application/json":
                payload = json.loads(raw_body.decode("utf-8"))
            elif content_type == "application/x-www-form-urlencoded":
                parsed = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
                payload = {key: values[0] for key, values in parsed.items()}
            else:
                raise ValueError("unsupported content type")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid_request_body"},
            )
            return

        agent_id = str(payload.get("agent", "")).strip()
        challenge_id = str(payload.get("challenge", "")).strip()
        candidate = str(payload.get("flag", "")).strip()

        if not AGENT_ID_PATTERN.fullmatch(agent_id):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "error": "invalid_agent",
                    "message": "agent는 영문·숫자·점·밑줄·하이픈 1~32자입니다.",
                },
            )
            return
        challenge = CHALLENGES_BY_ID.get(challenge_id)
        if not challenge:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid_challenge"},
            )
            return
        if not candidate or len(candidate) > 512:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid_flag"},
            )
            return

        candidate_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        correct = hmac.compare_digest(
            candidate_hash,
            challenge["flag_sha256"],
        )
        created_at = utc_now()
        user_agent = self.headers.get("User-Agent", "")[:256]

        with closing(db_connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO submissions (
                    created_at, source_ip, agent_id, challenge_id,
                    candidate_sha256, candidate_text, correct, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    source_ip,
                    agent_id,
                    challenge_id,
                    candidate_hash,
                    candidate,
                    int(correct),
                    user_agent,
                ),
            )
            first_solve = False
            if correct:
                solve_cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO solves (
                        agent_id, challenge_id, source_ip,
                        first_solved_at, submission_id
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id,
                        challenge_id,
                        source_ip,
                        created_at,
                        cursor.lastrowid,
                    ),
                )
                first_solve = solve_cursor.rowcount == 1

        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "correct": correct,
                "first_solve": first_solve,
                "agent": agent_id,
                "challenge": challenge_id,
                "submitted_at": created_at,
                "message": "CORRECT" if correct else "WRONG",
            },
        )

    def _public_leaderboard(self) -> dict:
        with closing(db_connect()) as connection:
            leaderboard_rows = connection.execute(
                """
                SELECT
                    agents.agent_id,
                    (
                        SELECT COUNT(*) FROM submissions AS s
                        WHERE s.agent_id = agents.agent_id
                    ) AS attempts,
                    (
                        SELECT COUNT(*) FROM solves AS v
                        WHERE v.agent_id = agents.agent_id
                    ) AS solves,
                    (
                        SELECT MAX(v.first_solved_at) FROM solves AS v
                        WHERE v.agent_id = agents.agent_id
                    ) AS last_solve_at
                FROM (
                    SELECT DISTINCT agent_id FROM submissions
                ) AS agents
                ORDER BY solves DESC, last_solve_at ASC, agents.agent_id ASC
                """
            ).fetchall()
            solve_rows = connection.execute(
                """
                SELECT agent_id, challenge_id, first_solved_at
                FROM solves
                ORDER BY first_solved_at DESC
                """
            ).fetchall()
            first_blood_rows = connection.execute(
                """
                SELECT agent_id, challenge_id, first_solved_at
                FROM solves
                ORDER BY first_solved_at ASC, submission_id ASC
                """
            ).fetchall()
            recent_submission_rows = connection.execute(
                """
                SELECT created_at, agent_id, challenge_id, correct
                FROM submissions
                ORDER BY id DESC
                LIMIT 20
                """
            ).fetchall()
            submission_count = connection.execute(
                "SELECT COUNT(*) FROM submissions"
            ).fetchone()[0]

        scorable_count = sum(
            1
            for challenge in CHALLENGES
            if challenge.get("status") in {"open", "file-only"}
        )
        solves_by_agent: dict[str, list[dict]] = {}
        for row in solve_rows:
            challenge = CHALLENGES_BY_ID.get(row["challenge_id"], {})
            solves_by_agent.setdefault(row["agent_id"], []).append(
                {
                    "challenge_id": row["challenge_id"],
                    "name": challenge.get("name", row["challenge_id"]),
                    "category": challenge.get("category", "other"),
                    "points": challenge.get("points", 0),
                    "first_solved_at": row["first_solved_at"],
                }
            )

        first_bloods_by_challenge: dict[str, list[dict]] = {}
        for row in first_blood_rows:
            solvers = first_bloods_by_challenge.setdefault(
                row["challenge_id"],
                [],
            )
            if len(solvers) >= 3:
                continue
            solvers.append(
                {
                    "rank": len(solvers) + 1,
                    "agent_id": row["agent_id"],
                    "first_solved_at": row["first_solved_at"],
                }
            )

        challenge_first_bloods = [
            {
                "challenge_id": challenge["id"],
                "name": challenge["name"],
                "category": challenge.get("category", "other"),
                "points": challenge.get("points", 0),
                "solvers": first_bloods_by_challenge.get(
                    challenge["id"],
                    [],
                ),
            }
            for challenge in CHALLENGES
            if challenge.get("status") in {"open", "file-only"}
        ]

        leaderboard = []
        for row in leaderboard_rows:
            entry = dict(row)
            entry["solved_challenges"] = solves_by_agent.get(
                row["agent_id"],
                [],
            )
            leaderboard.append(entry)

        return {
            "ok": True,
            "generated_at": utc_now(),
            "submissions": submission_count,
            "scorable_challenges": scorable_count,
            "leaderboard": leaderboard,
            "challenge_first_bloods": challenge_first_bloods,
            "recent_solves": [dict(row) for row in solve_rows[:20]],
            "recent_submissions": [
                dict(row) for row in recent_submission_rows
            ],
        }

    def _admin_overview(self) -> dict:
        with closing(db_connect()) as connection:
            summary_row = connection.execute(
                """
                SELECT
                    COUNT(*) AS submissions,
                    COALESCE(SUM(correct), 0) AS correct_submissions,
                    COUNT(DISTINCT agent_id) AS agents
                FROM submissions
                """
            ).fetchone()
            unique_solves = connection.execute(
                "SELECT COUNT(*) FROM solves"
            ).fetchone()[0]
            leaderboard_rows = connection.execute(
                """
                SELECT
                    agents.agent_id,
                    (
                        SELECT COUNT(*) FROM submissions AS s
                        WHERE s.agent_id = agents.agent_id
                    ) AS attempts,
                    (
                        SELECT COUNT(*) FROM solves AS v
                        WHERE v.agent_id = agents.agent_id
                    ) AS solves,
                    (
                        SELECT MAX(v.first_solved_at) FROM solves AS v
                        WHERE v.agent_id = agents.agent_id
                    ) AS last_solve_at
                FROM (
                    SELECT DISTINCT agent_id FROM submissions
                ) AS agents
                ORDER BY solves DESC, last_solve_at ASC, agents.agent_id ASC
                """
            ).fetchall()
            recent_rows = connection.execute(
                """
                SELECT
                    id, created_at, agent_id, challenge_id,
                    candidate_text AS submitted_value, correct
                FROM submissions
                ORDER BY id DESC
                LIMIT 200
                """
            ).fetchall()
            solve_rows = connection.execute(
                """
                SELECT
                    agent_id, challenge_id, first_solved_at
                FROM solves
                ORDER BY first_solved_at ASC
                """
            ).fetchall()

        return {
            "ok": True,
            "generated_at": utc_now(),
            "summary": {
                "submissions": summary_row["submissions"],
                "correct_submissions": summary_row["correct_submissions"],
                "unique_solves": unique_solves,
                "agents": summary_row["agents"],
                "scorable_challenges": sum(
                    1
                    for challenge in CHALLENGES
                    if challenge.get("status") in {"open", "file-only"}
                ),
            },
            "challenges": [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "category": item["category"],
                    "points": item["points"],
                }
                for item in CHALLENGES
            ],
            "leaderboard": [dict(row) for row in leaderboard_rows],
            "recent": [dict(row) for row in recent_rows],
            "solves": [dict(row) for row in solve_rows],
        }

    def log_message(self, format_string: str, *args) -> None:
        message = format_string % args
        print(
            f"{utc_now()} ip={self._client_ip()} "
            f'method={self.command} path="{self.path}" message="{message}"',
            flush=True,
        )


def main() -> None:
    initialize_database()
    server = PortalServer((LISTEN_HOST, LISTEN_PORT), PortalHandler)
    print(
        f"{utc_now()} HALCTF portal listening on "
        f"{LISTEN_HOST}:{LISTEN_PORT}; admin_ip={ADMIN_IP}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
