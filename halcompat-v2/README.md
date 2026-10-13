# EQSTHAL CTF · HalCompat V2

기본 EQSTHAL CTF와 함께 사용하는 HALCTF Player Preview 형식의 연습용 포털입니다.
기본판의 문제 서버 20개와 부모 폴더의 manifest / 첨부파일을 공유하고 별도 DB를 사용합니다.
기본 문제 서버를 먼저 시작해야 실행형 문제에 접속할 수 있습니다.

## 접속과 설정

- 공개 포털 / MCP: http://localhost:22080/
- 로컬 관리자: http://127.0.0.1:22079/admin
- 기존 문제 서버: 21081–21100

compose.yaml의 모든 environment 블록에서 PUBLIC_HOST, PUBLIC_BASE_URL,
MCP_ALLOWED_ORIGINS, PRACTICE_OPENAI_BASE_URL을 실제 접속 환경에 맞추세요.
localhost는 브라우저 로컬 확인용입니다. 다른 PC 또는 에이전트 컨테이너에는 접근 가능한
서버 주소가 필요합니다. 모델 서버와 에이전트는 별도로 준비합니다.

## 사용 흐름

1. 기본판에서 문제 서버를 시작합니다.
2. 이 폴더의 start.cmd 또는 start.ps1로 V2 포털을 시작합니다.
3. 브라우저에서 사용자 ID와 문제를 선택해 run을 발급합니다.
4. 발급된 env_file 설정을 에이전트 실행 환경에 전달합니다.
5. 에이전트가 run 전용 MCP 주소를 통해 문제 정보와 제출 기능을 사용합니다.

V2의 stop.cmd와 restart.cmd는 V2 포털만 대상으로 합니다.
기본판과 V2의 공개 관리자 경로는 차단되며 로컬 관리자 포트는 loopback 전용입니다.

## MCP 계약

list_ctfs, list_challenges, get_challenge, get_challenge_status, submit_flag,
request_hint, get_scoreboard, get_score_breakdown을 제공합니다.

run은 사용자와 문제 하나에 연결되며 6시간 뒤 만료됩니다.
MCP token은 발급 시 원문으로 전달하고 DB에는 SHA-256을 저장합니다.
HTTP access log의 token은 가려집니다. V2에서는 기본판의 수동 /api/submit이 비활성화됩니다.

문제 서버는 run마다 복제하지 않고 공유합니다. gVisor 격리와 공식 모델 / token 점수 산식은
재현하지 않습니다. run 발급 자체에 참가자 로그인이 없는 팀 내부 연습용 구성입니다.
