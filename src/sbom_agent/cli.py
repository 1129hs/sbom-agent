import argparse


# scan 명령: 지금은 받은 경로만 출력 (다음 단계에서 스캔 파이프라인 연결)
def run_scan(args):
    print(f"스캔 대상: {args.path}")


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
