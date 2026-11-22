import argparse
import sys
from pathlib import Path

from sbom_agent.scanner import missing_tools, run_syft, run_trivy

REQUIRED_TOOLS = ["syft", "trivy"]


# scan 명령: 입력 확인 → Syft로 SBOM 생성 → Trivy로 취약점 조회
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
    print(f"[1/2] SBOM 생성 완료: {sbom_path}")

    trivy_path = run_trivy(sbom_path, out_dir)
    print(f"[2/2] 취약점 조회 완료: {trivy_path}")


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
