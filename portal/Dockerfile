FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8080

WORKDIR /app

COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static
RUN mkdir -p /app/config

RUN addgroup -g 10001 -S halctf \
    && adduser -u 10001 -S -D -H -G halctf halctf \
    && mkdir -p /data \
    && chown -R halctf:halctf /app /data

USER 10001:10001

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"

CMD ["python", "/app/app.py"]
