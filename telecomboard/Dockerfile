# syntax=docker/dockerfile:1
FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
ARG EXTRAS=""
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install --no-cache ".${EXTRAS}"

FROM python:3.13-slim
RUN useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH SB_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1
USER 10001
WORKDIR /home/app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
ENTRYPOINT ["switchboard"]
CMD ["serve", "gateway", "--host", "0.0.0.0", "--port", "8000"]
