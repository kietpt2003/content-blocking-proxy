FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install . && useradd --uid 10001 --create-home proxy \
    && mkdir -p /state /app/config && chown -R proxy:proxy /state
USER proxy
VOLUME ["/state"]
EXPOSE 8080
ENTRYPOINT ["content-proxy"]
CMD ["run", "--config", "/app/config/proxy.yaml", "--state-dir", "/state", "--listen-host", "0.0.0.0", "--port", "8080"]

