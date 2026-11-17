import io

from PIL import Image


# 사용자가 올린 이미지 크기 읽기
def read_image_size(image_bytes):
    with Image.open(io.BytesIO(image_bytes)) as img:
        return img.size
