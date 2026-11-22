import shutil


# 이름 목록 중 PATH에서 찾을 수 없는(설치 안 된) 명령만 돌려줌
def missing_tools(names):
    return [name for name in names if shutil.which(name) is None]
