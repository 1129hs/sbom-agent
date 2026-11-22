import re
from pathlib import Path

# 패키지 이름과 import 이름이 다른 경우만 적어둠 (키는 소문자)
IMPORT_NAMES = {
    "pillow": "PIL",
    "python-jose": "jose",
    "python-dateutil": "dateutil",
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
}

# 검색에서 뺄 폴더 (가상환경, 설치된 라이브러리, 캐시)
SKIP_DIRS = {".venv", "venv", ".git", "node_modules", "site-packages", "__pycache__"}


# 패키지 이름 → 코드에서 쓰는 import 이름 (표에 없으면 '-'를 '_'로)
def import_name(pkg):
    key = pkg.lower()
    if key in IMPORT_NAMES:
        return IMPORT_NAMES[key]
    return key.replace("-", "_")


# 대상 폴더의 .py 파일에서 패키지를 import하는 줄을 찾음
def find_usage(target, pkg):
    target = Path(target)
    name = re.escape(import_name(pkg))
    # "import jose", "from jose import ...", "from jose.jwt import ..." 등
    pattern = re.compile(rf"^\s*(from|import)\s+{name}(\.|\s|,|$)")

    hits = []
    for path in sorted(target.rglob("*.py")):
        if SKIP_DIRS.intersection(path.parts):
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for lineno, line in enumerate(lines, start=1):
            if pattern.match(line):
                hits.append(
                    {
                        "file": path.relative_to(target).as_posix(),
                        "line": lineno,
                        "text": line.strip(),
                    }
                )
    return hits


# 사용 위치 목록을 LLM 프롬프트에 넣을 글로 변환
def format_usage(hits):
    if not hits:
        return "직접 import 없음"
    return "\n".join(f"{h['file']}:{h['line']}  {h['text']}" for h in hits)
