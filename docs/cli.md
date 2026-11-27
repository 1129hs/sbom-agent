# sbom-agent CLI

## sbom-agent scan

대상 폴더를 스캔해 취약점을 찾고, 코드 사용 위치를 근거로 영향을 판별합니다.

```
sbom-agent scan <path> [--out OUT] [--no-llm]
```

### 인자와 옵션

| 이름 | 필수 | 기본값 | 설명 |
| --- | --- | --- | --- |
| `path` | ✅ | | 스캔할 프로젝트 폴더 |
| `--out` | | `sbom-agent-out` | 결과 파일을 저장할 폴더 (없으면 생성) |
| `--no-llm` | | 꺼짐 | LLM 영향 판별 없이 스캔과 사용 위치 검색만 실행 |

### 환경 변수

| 이름 | 설명 |
| --- | --- |
| `OPENAI_API_KEY` | LLM 영향 판별에 사용. 없으면 안내 메시지를 출력하고 판별 단계만 건너뜀 (종료 코드 0) |

### 실행 순서

1. 대상 폴더가 있는지, `syft`와 `trivy`가 설치되어 있는지 확인
2. Syft로 SBOM 생성
3. Trivy로 취약점 조회 후 패키지 단위 목록으로 변환
4. 취약한 패키지마다 `.py` 파일에서 import 위치 검색
5. (`--no-llm`이 아니고 API 키가 있으면) 패키지마다 LLM 판별 + 규칙 검증

### 결과 파일 (`--out` 폴더)

| 파일 | 만드는 단계 | 내용 |
| --- | --- | --- |
| `sbom.cdx.json` | 2 | Syft가 만든 CycloneDX SBOM |
| `trivy.json` | 3 | Trivy 원본 결과 |
| `vulns.json` | 3 | 취약점 목록 (아래 형식) |
| `usage.json` | 4 | 패키지별 import 위치 (아래 형식) |
| `triage.json` | 5 | 패키지별 LLM 판별 결과 (아래 형식) |

`vulns.json`: 취약점 하나당 객체 하나. 수정 버전이 없으면 `fixed`는 `null`.

```json
[
  {
    "pkg": "python-jose",
    "installed": "3.3.0",
    "id": "CVE-2026-85394",
    "severity": "CRITICAL",
    "fixed": null,
    "title": "..."
  }
]
```

`usage.json`: 패키지 이름 → import 위치 목록. 직접 import가 없으면 빈 리스트.

```json
{
  "pillow": [{ "file": "upload.py", "line": 3, "text": "from PIL import Image" }],
  "anyio": []
}
```

`triage.json`: 패키지마다 LLM 원문(`raw`)과 파싱·검증된 결과(`parsed`). JSON 파싱에 실패하면 `parsed`는 `null`.

```json
[
  {
    "package": "python-jose",
    "model": "gpt-5-mini",
    "parsed": {
      "impact": "영향 있음",
      "action": "replace",
      "recommended_version": null,
      "rule_warnings": ["수정 버전이 없는 취약점이 있어 업그레이드만으로 해결되지 않음: CVE-2026-85394"]
    },
    "raw": "..."
  }
]
```

`parsed`에는 위 필드 외에 `package`, `installed_version`, `reason`(판단 이유), `evidence`(근거), `action_detail`(조치 설명), `cited_ids`(인용한 취약점 ID)가 함께 들어 있습니다.

`parsed`의 주요 필드:

- `impact`: `영향 있음` / `낮음` / `해당 없음` / `확인 필요`
- `action`: `upgrade` / `replace` / `monitor` / `none`
- `rule_warnings`: 규칙 검증이 결과를 바꿨을 때의 사유 (없으면 빈 리스트)

### 종료 코드

| 코드 | 의미 |
| --- | --- |
| `0` | 정상 종료 (LLM 단계를 건너뛴 경우 포함) |
| `1` | 대상 폴더가 없거나 `syft`·`trivy`가 설치되어 있지 않음 |

Syft나 Trivy 실행 자체가 실패하면 파이썬 에러 메시지와 함께 0이 아닌 코드로 종료됩니다.

### 예시

```bash
# 스캔 + 사용 위치 + LLM 판별
sbom-agent scan ./my-service

# LLM 없이, 결과를 다른 폴더에
sbom-agent scan ./my-service --no-llm --out ./reports/my-service

# Docker
docker run --rm -v "$(pwd)":/work -e OPENAI_API_KEY sbom-agent scan my-service
```
