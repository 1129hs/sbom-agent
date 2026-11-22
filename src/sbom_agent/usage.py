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


# 패키지 이름 → 코드에서 쓰는 import 이름 (표에 없으면 '-'를 '_'로)
def import_name(pkg):
    key = pkg.lower()
    if key in IMPORT_NAMES:
        return IMPORT_NAMES[key]
    return key.replace("-", "_")
