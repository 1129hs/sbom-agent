import json
from collections import defaultdict

from sbom_agent.rules import validate_action

MODEL = "gpt-5-mini"

# 코드 검색 범위 설명 (사용 위치와 함께 LLM에게 전달)
SEARCH_SCOPE = (
    "검색 범위: 대상 폴더의 모든 .py 파일 (가상환경 제외), import 문만 검색\n"
    "직접 import가 없어도 프레임워크 같은 다른 라이브러리를 통해 실행 중에 쓰일 수 있다. "
    '이 경우 "해당 없음"이 아니라 "낮음" 또는 "확인 필요"로 판단한다.'
)

SYSTEM_PROMPT = """너는 SW 공급망 보안 분석가다. 주어진 입력만 근거로 판단한다.

규칙
1. 입력에 없는 CVE/GHSA 번호나 버전을 만들어내지 않는다. 모르면 null로 둔다.
2. impact는 "영향 있음", "낮음", "해당 없음", "확인 필요" 중 하나로만 답한다.
3. 코드 사용 정보가 주어지지 않았거나 판단 근거가 부족하면 "확인 필요"를 쓴다.
4. 반드시 아래 JSON 형식만 출력한다. 설명 문장이나 코드 블록 기호를 붙이지 않는다.

{
  "package": "",
  "installed_version": "",
  "impact": "",
  "reason": "",
  "evidence": [],
  "action": "upgrade | replace | monitor | none",
  "recommended_version": null,
  "action_detail": "",
  "cited_ids": []
}"""


# 취약점 리스트를 패키지별로 묶기
def group_by_package(vulns):
    grouped = defaultdict(list)
    for v in vulns:
        grouped[v["pkg"]].append(v)
    return grouped


# 취약점 파일을 읽어 패키지별로 묶기
def load_vulns(path):
    with open(path, encoding="utf-8") as f:
        return group_by_package(json.load(f))


# 유저 프롬프트 만들기 (usage가 None이면 코드 정보 없이 취약점만)
def build_prompt(pkg, vulns, usage):
    installed = vulns[0]["installed"]
    vuln_list = [
        {
            "id": v["id"],
            "severity": v["severity"],
            "fixed": v["fixed"],
            "title": v["title"],
        }
        for v in vulns
    ]
    prompt = (
        f"패키지: {pkg}\n"
        f"설치 버전: {installed}\n"
        f"취약점 수: {len(vuln_list)}\n"
        f"취약점 목록:\n{json.dumps(vuln_list, ensure_ascii=False, indent=2)}\n"
    )
    if usage is not None:
        prompt += f"\n서비스 코드 검색 결과\n{SEARCH_SCOPE}\n\n{usage}\n"
    prompt += "\n이 패키지가 이 서비스에 실제로 영향을 주는지 판단하고 조치안을 JSON으로 답하라."
    return prompt


# LLM 호출
def call_llm(client, system_prompt, user_prompt):
    response = client.responses.create(
        model=MODEL,
        instructions=system_prompt,
        input=user_prompt,
    )
    return response.output_text


# 응답 텍스트를 JSON으로 파싱 (코드 블록 기호가 붙어 와도 처리)
def parse_json(text):
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.removeprefix("json")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


# 패키지 하나 판단: 프롬프트 → LLM → 파싱 → 규칙 검증
def triage_package(client, pkg, vulns, usage):
    raw = call_llm(client, SYSTEM_PROMPT, build_prompt(pkg, vulns, usage))
    parsed = parse_json(raw)
    # 파싱에 실패하면 규칙 검증은 건너뛰고 원문만 남김
    if parsed is not None:
        parsed = validate_action(vulns, parsed)
    return {"package": pkg, "model": MODEL, "parsed": parsed, "raw": raw}
