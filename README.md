# sbom-agent

의존성 취약점 중 **실제로 코드에 영향을 주는 것**을 골라내고 조치안을 정리하는 도구입니다. CLI로 스캔하고, 결과는 터미널이나 웹 대시보드에서 볼 수 있습니다.

## 왜 만들었나

취약점 스캐너를 돌리면 수십~수백 건이 나오지만, 대부분은 코드에서 쓰지 않는 패키지이거나 버전 하나만 올리면 함께 해결되는 것들입니다. 무엇을 먼저 고쳐야 할지 판단하는 데 시간이 오래 걸립니다.

sbom-agent는 스캔 결과에 **코드 사용 위치**를 붙여 LLM이 영향을 판단하게 하고, LLM의 답을 **규칙으로 한 번 더 검증**합니다.

## 동작 흐름

```
대상 폴더
  → Syft: SBOM 생성 (직접·전이 의존성)
  → Trivy: 패키지별 취약점과 수정 버전 조회
  → 코드 검색: 취약한 패키지를 import하는 위치 찾기
  → LLM: 영향 판단 (영향 있음 / 낮음 / 해당 없음 / 확인 필요) + 조치안
  → 규칙 검증: LLM 답과 취약점 데이터가 모순되면 바로잡고 경고
```

규칙 검증 예시: 수정 버전이 없는 취약점이 남아 있는데 LLM이 `upgrade`를 권하면, `replace`로 바꾸고 추천 버전을 지운 뒤 경고를 남깁니다. 실험에서 LLM이 설명에는 "교체 검토"라고 쓰고 구조화 필드에는 `upgrade`를 넣는 모순을 발견해 추가한 규칙입니다. ([실험 01](experiments/01_llm_triage.md))

## 실행 예시

레포에 포함된 데모 앱(`tests/fixtures/demo-app/`)을 스캔한 결과입니다.

```
$ sbom-agent scan ./tests/fixtures/demo-app
스캔 대상: tests/fixtures/demo-app
SBOM 생성 완료: sbom-agent-out/sbom.cdx.json
취약점 조회 완료: sbom-agent-out/trivy.json
취약점 66건 · 패키지 3개 → sbom-agent-out/vulns.json

코드 사용 위치 → sbom-agent-out/usage.json
  anyio: 직접 import 없음
  pillow: upload.py:3
  python-jose: auth.py:1

영향 판별 (LLM + 규칙 검증)
  anyio: impact=확인 필요 | action=monitor | recommended=4.14.2
  pillow: impact=영향 있음 | action=upgrade | recommended=13.0.0
  python-jose: impact=영향 있음 | action=replace | recommended=None
    ⚠ 규칙 검증: 수정 버전이 없는 취약점이 있어 업그레이드만으로 해결되지 않음: CVE-2026-85394
→ sbom-agent-out/triage.json
```

LLM 판단은 실행할 때마다 달라질 수 있습니다.

## 웹 대시보드

스캔 결과를 웹 화면으로 볼 수 있습니다. 영향도 순으로 정렬된 조치 목록과, 패키지별 판단 근거·코드 사용 위치·취약점·규칙 검증 경고를 보여줍니다.

```bash
sbom-agent scan ./tests/fixtures/demo-app
sbom-agent serve --target demo-app
# http://127.0.0.1:8000
```

## 설치와 실행

### Docker (권장)

Syft와 Trivy가 이미지에 포함되어 있어 Docker만 있으면 됩니다.

```bash
docker build -t sbom-agent .

# 스캔
docker run --rm \
  -v "$(pwd)":/work \
  -v ~/Library/Caches/trivy:/root/.cache/trivy \
  sbom-agent scan <경로> --no-llm

# 웹 대시보드 (http://localhost:8000)
docker run --rm -p 8000:8000 -v "$(pwd)":/work sbom-agent serve --host 0.0.0.0
```

- `-v "$(pwd)":/work`: 현재 폴더를 컨테이너에 연결합니다. 결과는 `./sbom-agent-out/`에 저장됩니다.
- `-v ~/Library/Caches/trivy:...`: Trivy 취약점 DB를 재사용합니다 (macOS 기준). 없으면 실행할 때마다 DB를 새로 받습니다.
- LLM 판단까지 하려면 `--no-llm`을 빼고 `-e OPENAI_API_KEY`를 추가합니다.
- 웹은 컨테이너 밖에서 접속할 수 있도록 `--host 0.0.0.0`과 `-p 8000:8000`이 필요합니다.

### 로컬

Python 3.12 이상, [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy)가 필요합니다.

```bash
git clone https://github.com/1129hs/sbom-agent.git
cd sbom-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e . --no-deps

sbom-agent scan <경로>
sbom-agent serve
```

명령어와 옵션은 [docs/cli.md](docs/cli.md)에 정리되어 있습니다.

## LLM에 보내는 데이터

LLM 판단 단계에서는 패키지별 **취약점 목록**과 **import 줄(파일 경로, 줄 번호, 코드 한 줄)**이 OpenAI API로 전송됩니다. 외부로 보내면 안 되는 코드라면 `--no-llm`으로 스캔과 사용 위치 검색만 실행하세요.

## 개발

```bash
pip install -r requirements-dev.txt
pip install -e . --no-deps

ruff check src/ tests/
ruff format --check src/ tests/
pytest
```

- `pyproject.toml`: 직접 의존성(범위) / `requirements*.txt`: `pip-compile`로 만든 잠금 파일(고정 버전)
- CI(GitHub Actions): push·PR마다 린트, 포맷 검사, 테스트, Docker 이미지 빌드를 실행하고, 실패하면 main에 머지할 수 없습니다.

## 구조

```
src/sbom_agent/
  cli.py       # sbom-agent 명령 (scan, serve)
  scanner.py   # Syft·Trivy 실행, Trivy 결과 변환
  usage.py     # 패키지 이름 → import 이름, 코드 사용 위치 검색
  triage.py    # LLM 프롬프트, 호출, 응답 파싱
  rules.py     # LLM 결과 규칙 검증
  report.py    # 결과 파일을 패키지별 리포트로 합치기
  web.py       # FastAPI 대시보드
  templates/   # Jinja2 화면 (목록, 상세)
tests/
  fixtures/demo-app/   # 일부러 취약한 버전을 쓰는 데모 앱
experiments/           # 실험 기록
```

## 한계

- 코드 사용 위치는 Python의 `import` 문만 찾습니다. 함수 호출 경로나 전이 의존성(예: FastAPI가 내부에서 쓰는 anyio)은 아직 분석하지 않습니다.
- 패키지 이름과 import 이름이 다른 경우(`pillow` → `PIL`)는 변환표로 처리하며, 표에 없는 패키지는 놓칠 수 있습니다.
- 한 번에 폴더 하나만 스캔합니다.
- 웹 대시보드는 스캔 결과를 보여주기만 하며, 스캔은 CLI로 실행합니다.

## 계획

- 조치 그룹화: 취약점 개수가 아니라 "조치 몇 번이면 끝나는지"로 묶기 (같은 패키지 → 여러 저장소 → 전이 의존성 순)
- 여러 저장소의 공통 의존성 지도
- 웹에서 스캔 시작하기, 웹 대시보드 배포
- Gradle(Kotlin/Java) 프로젝트 지원
