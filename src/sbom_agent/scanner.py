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
