import argparse
import sys
from pathlib import Path

from sbom_agent.scanner import missing_tools

REQUIRED_TOOLS = ["syft", "trivy"]


# scan 명령: 입력 확인 후 스캔 (파이프라인은 다음 단계에서 연결)
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

    print(f"스캔 대상: {target}")


def main():
    parser = argparse.ArgumentParser(
        prog="sbom-agent",
        description="의존성 취약점의 실제 영향을 판별하고 조치안을 정리합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # sbom-agent scan <경로>
    scan_parser = subparsers.add_parser("scan", help="폴더를 스캔합니다")
    scan_parser.add_argument("path", help="스캔할 프로젝트 폴더 경로")
    scan_parser.set_defaults(func=run_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
