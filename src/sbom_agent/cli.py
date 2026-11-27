import argparse
import json
import os
import sys
from pathlib import Path

from sbom_agent.scanner import missing_tools, parse_trivy, run_syft, run_trivy
from sbom_agent.triage import group_by_package, triage_package
from sbom_agent.usage import find_usage, format_usage

REQUIRED_TOOLS = ["syft", "trivy"]


# 결과를 JSON 파일로 저장 (한글이 깨지지 않게)
def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# 패키지마다 LLM 판단 + 규칙 검증, 결과 요약 출력
def run_triage(vulns, usage, out_dir):
    # openai는 LLM을 쓸 때만 불러옴 (--no-llm이면 설치·로딩 불필요)
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"].strip())
    results = []
    print("\n영향 판별 (LLM + 규칙 검증)")
    for pkg, pkg_vulns in sorted(group_by_package(vulns).items()):
        result = triage_package(client, pkg, pkg_vulns, format_usage(usage[pkg]))
        results.append(result)

        parsed = result["parsed"]
        if parsed is None:
            print(f"  {pkg}: JSON 파싱 실패 (원문은 triage.json에 저장)")
            continue
        print(
            f"  {pkg}: impact={parsed.get('impact')} | "
            f"action={parsed.get('action')} | "
            f"recommended={parsed.get('recommended_version')}"
        )
        for warning in parsed["rule_warnings"]:
            print(f"    ⚠ 규칙 검증: {warning}")

    triage_path = out_dir / "triage.json"
    write_json(triage_path, results)
    print(f"→ {triage_path}")


# scan 명령: 입력 확인 → SBOM → 취약점 조회 → 코드 사용 위치 → 영향 판별
def run_scan(args):
    target = Path(args.path)
    if not target.is_dir():
        print(f"폴더를 찾을 수 없습니다: {target}", file=sys.stderr)
        sys.exit(1)

    missing = missing_tools(REQUIRED_TOOLS)
    if missing:
        print(
            f"필요한 도구가 설치되어 있지 않습니다: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"스캔 대상: {target}")

    sbom_path = run_syft(target, out_dir)
    print(f"SBOM 생성 완료: {sbom_path}")

    trivy_path = run_trivy(sbom_path, out_dir)
    print(f"취약점 조회 완료: {trivy_path}")

    vulns = parse_trivy(trivy_path)
    vulns_path = out_dir / "vulns.json"
    write_json(vulns_path, vulns)
    packages = sorted({v["pkg"] for v in vulns})
    print(f"취약점 {len(vulns)}건 · 패키지 {len(packages)}개 → {vulns_path}")

    # 취약한 패키지마다 코드에서 import하는 위치 찾기
    usage = {pkg: find_usage(target, pkg) for pkg in packages}
    usage_path = out_dir / "usage.json"
    write_json(usage_path, usage)
    print(f"\n코드 사용 위치 → {usage_path}")
    for pkg, hits in usage.items():
        if hits:
            places = ", ".join(f"{h['file']}:{h['line']}" for h in hits)
            print(f"  {pkg}: {places}")
        else:
            print(f"  {pkg}: 직접 import 없음")

    # LLM 단계는 옵션이나 API 키가 없으면 건너뜀 (스캔 결과는 이미 저장됨)
    if args.no_llm:
        print("\n--no-llm: 영향 판별을 건너뜁니다.")
        return
    if not os.getenv("OPENAI_API_KEY"):
        print("\nOPENAI_API_KEY가 없어 영향 판별을 건너뜁니다.")
        return
    run_triage(vulns, usage, out_dir)


# serve 명령: 스캔 결과 폴더를 웹 대시보드로 보여줌
def run_serve(args):
    out_dir = Path(args.out)
    if not (out_dir / "vulns.json").exists():
        print(
            f"스캔 결과가 없습니다: {out_dir}/vulns.json (먼저 sbom-agent scan 실행)",
            file=sys.stderr,
        )
        sys.exit(1)

    # 웹 관련 라이브러리는 serve할 때만 불러옴
    import uvicorn

    from sbom_agent.web import create_app

    print(f"대시보드: http://{args.host}:{args.port}  (종료: Ctrl+C)")
    uvicorn.run(create_app(out_dir, target=args.target), host=args.host, port=args.port)


def main():
    parser = argparse.ArgumentParser(
        prog="sbom-agent",
        description="의존성 취약점의 실제 영향을 판별하고 조치안을 정리합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # sbom-agent scan <경로> [--out 폴더] [--no-llm]
    scan_parser = subparsers.add_parser("scan", help="폴더를 스캔합니다")
    scan_parser.add_argument("path", help="스캔할 프로젝트 폴더 경로")
    scan_parser.add_argument(
        "--out",
        default="sbom-agent-out",
        help="결과를 저장할 폴더 (기본: sbom-agent-out)",
    )
    scan_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="LLM 영향 판별 없이 스캔과 사용 위치 검색만 실행",
    )
    scan_parser.set_defaults(func=run_scan)

    # sbom-agent serve [--out 폴더] [--host] [--port] [--target 이름]
    serve_parser = subparsers.add_parser("serve", help="스캔 결과를 웹으로 봅니다")
    serve_parser.add_argument(
        "--out",
        default="sbom-agent-out",
        help="스캔 결과 폴더 (기본: sbom-agent-out)",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="기본: 127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000, help="기본: 8000")
    serve_parser.add_argument("--target", help="화면에 표시할 스캔 대상 이름")
    serve_parser.set_defaults(func=run_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
