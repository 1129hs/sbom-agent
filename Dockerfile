FROM python:3.13-slim

# 로컬과 같은 버전으로 고정
ARG SYFT_VERSION=1.55.0
ARG TRIVY_VERSION=0.76.1

# Syft·Trivy 설치 (공식 설치 스크립트, CPU 종류는 스크립트가 알아서 맞춤)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
       | sh -s -- -b /usr/local/bin v${SYFT_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
       | sh -s -- -b /usr/local/bin v${TRIVY_VERSION} \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 먼저 설치 (코드만 바뀌면 이 단계는 캐시 재사용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 그다음 코드 복사 후 sbom-agent 설치
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

# 스캔할 폴더를 여기에 연결해서 사용
WORKDIR /work
ENTRYPOINT ["sbom-agent"]
CMD ["--help"]
