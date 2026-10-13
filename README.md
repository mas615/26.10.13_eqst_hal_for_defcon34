# 26.10.13_eqst_hal_for_defcon34

EQSTHAL CTF: 팀원과 CTF 에이전트가 같은 문제를 풀고 결과를 비교하는 연습 플랫폼입니다.
DEF CON 34 AI Village / HALCTF 형식을 참고한 팀 연습용 구현이며 공식 실행 환경의 복제본은 아닙니다.

## 구성

- 문제 27개: 실행형 20개(HTTP 16개, TCP 4개), 파일형 7개
- 문제 목록, 플레이어 첨부파일 20개, 플래그 제출
- 공개 리더보드, 에이전트별 해결 목록, 문제별 최초 해결자 상위 3명
- 로컬 관리자 화면과 제출 원문 조회
- 선택적으로 실행하는 HalCompat V2 포털과 MCP 인터페이스

기본 Compose는 공개 포털, 관리자 포털, 문제 서버 20개로 총 22개 컨테이너를 생성합니다.
AI 모델과 풀이 에이전트는 별도로 준비하며 시작 스크립트가 자동 실행하지 않습니다.

## 준비

- Intel/AMD 64비트 Windows와 Docker Desktop의 Linux containers
- Docker Compose 및 이미지 다운로드를 위한 인터넷 연결
- 사용 가능한 TCP 포트 21079–21100, V2 사용 시 22079–22080 추가
- 기존 네트워크와 충돌하지 않는 Docker subnet 172.20.0.0/16, V2는 172.21.0.0/16

문제 이미지는 linux/amd64용입니다. ARM Mac에서는 에뮬레이션과 별도 호환성 확인이 필요합니다.
.cmd 실행기는 Windows용이며 Linux/macOS에서는 Compose를 직접 사용합니다.
다른 환경에서는 관리자 접속의 실제 소켓 IP와 allowlist가 일치하는지도 확인해야 합니다.

문제별 메모리 제한은 256 또는 512 MiB입니다. 기본 Compose의 모든 메모리 제한 합계는
약 9.44 GiB이며, 실제 사용량이나 최소 필요 RAM을 뜻하지 않습니다.

## Windows에서 시작

1. 저장소를 clone하고 Docker Desktop을 실행합니다.
2. 혼자 로컬에서 확인할 경우 기본 localhost 설정을 사용할 수 있습니다.
3. 다른 PC나 에이전트 컨테이너에서 접속한다면 아래 주소 설정을 먼저 변경합니다.
4. 저장소 루트의 start.cmd를 실행합니다.

| 서비스 | 기본 주소 / 포트 |
|---|---|
| 공개 포털 | http://localhost:21080/ |
| 로컬 관리자 | http://127.0.0.1:21079/admin |
| 실행형 문제 | TCP 21081–21100 |

시작 스크립트는 문제 이미지를 내려받고 포털 및 Orange 계열 보강 이미지를 빌드한 뒤
백그라운드로 시작합니다. 공개 포털과 관리자 health 응답을 확인하고 접속 주소를 출력합니다.
브라우저에서 에이전트 ID, 문제, 플래그를 제출하면 리더보드가 5초마다 갱신됩니다.
기본판 순위는 해결 문제 수와 마지막 해결 시각을 기준으로 정합니다.

## 팀 접속 주소

루트 compose.yaml의 portal, admin-portal 두 서비스에 있는 PUBLIC_HOST를
참가자와 에이전트가 접근할 서버 IP 또는 도메인으로 변경하세요.
이 값에는 http://나 포트를 넣지 않습니다. 포털이 문제 링크를 다시 작성하므로
challenges.json의 target을 각각 고칠 필요는 없습니다.

컨테이너에서 실행하는 에이전트에게 localhost는 에이전트 컨테이너 자신을 뜻합니다.
에이전트에서 실제로 접근 가능한 서버 주소를 사용하세요.

공개 포털과 문제 포트는 0.0.0.0에 바인딩됩니다. 방화벽과 공유기 설정은 자동 변경하지 않습니다.
의도적으로 취약한 CTF 문제이므로 신뢰하는 참가자의 격리된 연습 환경에서 운영하세요.
관리자 포트 21079와 22079는 loopback 전용으로 유지합니다.

## HalCompat V2 (선택)

기본 문제 서버를 먼저 시작한 뒤 halcompat-v2/start.cmd를 실행합니다.

- 공개 포털 / MCP: http://localhost:22080/
- 로컬 관리자: http://127.0.0.1:22079/admin
- 포털 컨테이너 2개 추가, 기본판과 문제 서버 및 첨부파일 공유, 별도 DB 사용

다른 PC나 에이전트에서 사용할 때는 halcompat-v2/compose.yaml 안의 모든 environment
블록에서 PUBLIC_HOST, PUBLIC_BASE_URL, MCP_ALLOWED_ORIGINS,
PRACTICE_OPENAI_BASE_URL을 실제 접속 환경에 맞춰 일관되게 변경하세요.
PUBLIC_BASE_URL과 MCP_ALLOWED_ORIGINS에는 포트를 포함한 전체 URL을 사용합니다.

모델 API 기본값은 http://host.docker.internal:11434/v1 입니다.
모델 서버를 함께 설치하거나 시작하지는 않습니다.
자세한 흐름은 [V2 README](halcompat-v2/README.md)를 참고하세요.

## 중지와 초기화

- stop.cmd: 기본판 컨테이너와 Compose 네트워크를 제거합니다. 이미지와 리더보드 볼륨은 보존합니다.
- start.cmd: 중지 후 다시 시작하거나 변경된 소스로 다시 빌드합니다.
- restart.cmd: 남아 있는 기존 컨테이너를 재시작합니다. stop.cmd 뒤에는 start.cmd를 사용하세요.
- reset.cmd: RESET 입력 후 기본판 컨테이너, 데이터 볼륨, 서비스 이미지를 삭제합니다.
  이어서 Docker 전체 builder cache도 정리하므로 다른 프로젝트의 빌드 캐시에도 영향을 줍니다.
- V2는 halcompat-v2 폴더 안의 시작·중지·재시작 스크립트로 별도 관리합니다.

리더보드는 Docker named volume에 저장되며 Git에는 포함되지 않습니다.
새 PC에서는 빈 리더보드로 시작합니다. 관리자 감사용 제출 원문에는 정답도 포함될 수 있으므로
운영 DB를 공개 저장소에 넣지 마세요. 공개 API에는 제출 원문과 source_ip가 노출되지 않도록
구성했습니다. 참가자 ID는 자유 입력이며 팀 내부 연습용입니다.

## 검증

Compose config는 구성만 검사하고 컨테이너를 시작하지 않습니다.
Python 통합 테스트는 임시 DB와 loopback 테스트 서버를 사용하며 실제 문제 서버를 실행하지 않습니다.

    docker compose -f compose.yaml config --quiet
    docker compose -f halcompat-v2/compose.yaml config --quiet
    python -m unittest discover -s portal/tests -v
    python -m unittest discover -s halcompat-v2/tests -v

latest 등 변경 가능한 이미지 태그를 사용합니다. 장기적으로 동일한 이미지 버전을 재현하려면
digest 고정이나 별도 이미지 보관이 필요합니다.

## 출처와 게시 범위

문제와 llmctf/* 이미지의 출처는
[NYU CTF Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) 및 원 CSAW CTF 문제입니다.
관련 고지는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를 참고하세요.

포털, 배포 설정, 플레이어 첨부파일을 배포합니다. 원 운영 환경의 인수인계 문서, 대화 기록,
인증 정보, 정답 문서, 제출 DB, Docker 이미지 및 풀이 에이전트는 포함하지 않습니다.
