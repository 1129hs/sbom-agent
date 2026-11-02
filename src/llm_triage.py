import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from openai import OpenAI

# 경로 설정
ROOT = Path(__file__).resolve().parent.parent
VULNS_PATH = ROOT / "data" / "inputs" / "vulns.json"
USAGE_PATH = ROOT / "data" / "inputs" / "usage.txt"
OUTPUT_DIR = ROOT / "data" / "outputs"

MODEL = "gpt-5-mini"

# 코드 검색 범위 설명 (B 조건에서 LLM에게 함께 전달)
SEARCH_SCOPE = (
    "검색 범위: 서비스 백엔드의 모든 .py 파일 (가상환경 제외)\n"
    "검색 패턴: from PIL, import PIL, from jose, import jose, from anyio, import anyio, "
    "jwt.encode, jwt.decode, JWTError\n"
    "아래 결과에 어떤 패키지가 나오지 않으면, 서비스 코드에서 그 패키지를 직접 import하지 않는다는 뜻이다."
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


# 취약점 목록을 패키지별로 묶기
def load_vulns(path):
    with open(path, encoding="utf-8") as f:
        vulns = json.load(f)
    grouped = defaultdict(list)
    for v in vulns:
        grouped[v["pkg"]].append(v)
    return grouped


# 코드 사용 위치 읽기 (로컬 절대경로는 지워서 전달)
def load_usage(path):
    text = Path(path).read_text(encoding="utf-8")
    home_prefix = str(Path.home()) + "/wifi_web-platform/"
    return text.replace(home_prefix, "")


# 유저 프롬프트 만들기 (usage가 None이면 A 조건)
def build_prompt(pkg, vulns, usage):
    installed = vulns[0]["installed"]
    vuln_list = [
        {"id": v["id"], "severity": v["severity"], "fixed": v["fixed"], "title": v["title"]}
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
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("A", "B"):
        print("사용법: python src/llm_triage.py A|B")
        sys.exit(1)
    condition = sys.argv[1]

    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY가 설정되지 않았습니다.")
        sys.exit(1)

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"].strip())
    grouped = load_vulns(VULNS_PATH)
    usage = load_usage(USAGE_PATH) if condition == "B" else None
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for pkg, vulns in grouped.items():
        user_prompt = build_prompt(pkg, vulns, usage)
        raw = call_llm(client, SYSTEM_PROMPT, user_prompt)
        parsed = parse_json(raw)

        # 원문과 파싱 결과를 함께 저장 (파싱 실패도 기록에 남기기)
        result = {
            "condition": condition,
            "model": MODEL,
            "package": pkg,
            "parsed": parsed,
            "raw": raw,
        }
        out_path = OUTPUT_DIR / f"{condition}_{pkg}.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        if parsed is None:
            print(f"[{condition}] {pkg}: JSON 파싱 실패 -> {out_path.name} 확인")
        else:
            print(
                f"[{condition}] {pkg}: impact={parsed.get('impact')} | "
                f"action={parsed.get('action')} | "
                f"recommended={parsed.get('recommended_version')}"
            )


if __name__ == "__main__":
    main()