import json
import shutil
import subprocess
from pathlib import Path


# 이름 목록 중 PATH에서 찾을 수 없는(설치 안 된) 명령만 돌려줌
def missing_tools(names):
    return [name for name in names if shutil.which(name) is None]


# Syft로 대상 폴더의 SBOM(CycloneDX JSON) 생성
def run_syft(target, out_dir):
    sbom_path = Path(out_dir) / "sbom.cdx.json"
    subprocess.run(
        ["syft", str(target), "-o", f"cyclonedx-json={sbom_path}"],
        check=True,
        capture_output=True,
    )
    return sbom_path


# Trivy로 SBOM의 취약점 조회
def run_trivy(sbom_path, out_dir):
    trivy_path = Path(out_dir) / "trivy.json"
    subprocess.run(
        ["trivy", "sbom", str(sbom_path), "-f", "json", "-o", str(trivy_path)],
        check=True,
        capture_output=True,
    )
    return trivy_path


# Trivy 결과를 triage가 읽는 취약점 목록 형식으로 변환
def parse_trivy(path):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    vulns = []
    for result in report.get("Results", []):
        # 취약점이 없는 Target은 키가 없거나 null
        for v in result.get("Vulnerabilities") or []:
            vulns.append(
                {
                    "pkg": v["PkgName"],
                    "installed": v["InstalledVersion"],
                    "id": v["VulnerabilityID"],
                    "severity": v["Severity"],
                    # 수정 버전이 없으면 Trivy는 빈 문자열을 줌 → None으로 통일
                    "fixed": v.get("FixedVersion") or None,
                    "title": v.get("Title", ""),
                }
            )
    return vulns
