import argparse
import json
import sys
from pathlib import Path

from sbom_agent.scanner import missing_tools, parse_trivy, run_syft, run_trivy
from sbom_agent.usage import find_usage

REQUIRED_TOOLS = ["syft", "trivy"]


# 결과를 JSON 파일로 저장 (한글이 깨지지 않게)
def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# scan 명령: 입력 확인 → SBOM → 취약점 조회 → 코드 사용 위치
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


def main():
    parser = argparse.ArgumentParser(
        prog="sbom-agent",
        description="의존성 취약점의 실제 영향을 판별하고 조치안을 정리합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # sbom-agent scan <경로> [--out 폴더]
    scan_parser = subparsers.add_parser("scan", help="폴더를 스캔합니다")
    scan_parser.add_argument("path", help="스캔할 프로젝트 폴더 경로")
    scan_parser.add_argument(
        "--out",
        default="sbom-agent-out",
        help="결과를 저장할 폴더 (기본: sbom-agent-out)",
    )
    scan_parser.set_defaults(func=run_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
