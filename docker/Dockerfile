# Multi-stage: (1) UI build, (2) wheelhouse, (3) runtime. The runtime stage installs from the local wheelhouse only
# (--no-index) so the final image never reaches the network when built from a prepared bundle context (§10).

FROM node:20-slim AS ui
WORKDIR /ui
RUN corepack enable
COPY ui/package.json ui/pnpm-lock.yaml* ./
RUN if [ -f pnpm-lock.yaml ]; then pnpm install --frozen-lockfile; else mkdir -p dist; fi
COPY ui/ ./
RUN if [ -f package.json ] && [ -f pnpm-lock.yaml ]; then pnpm build; else mkdir -p dist; fi

FROM python:3.12-slim AS wheels
WORKDIR /w
COPY requirements.lock* pyproject.toml ./
# Online build machine: resolve once into a wheelhouse. Offline rebuild: ship ./wheelhouse in the context and skip this.
COPY wheelhouse /w/wheelhouse
RUN set -e; mkdir -p wheelhouse; \
    if ! ls wheelhouse/*.whl >/dev/null 2>&1; then \
      if [ -f requirements.lock ]; then pip download -d wheelhouse -r requirements.lock; \
      else pip install --no-cache-dir pip-tools >/dev/null && pip-compile -q -o /tmp/req.txt pyproject.toml && pip download -d wheelhouse -r /tmp/req.txt; fi; \
    fi

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 ULPF_CONFIG=/app/configs/ulpf.yaml
RUN useradd --system --uid 10001 --home /app ulpf && mkdir -p /app /data && chown ulpf /data
WORKDIR /app
COPY --from=wheels /w/wheelhouse /tmp/wheelhouse
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheelhouse . && rm -rf /tmp/wheelhouse
COPY packs ./packs
COPY configs ./configs
COPY docker/fwd.py ./fwd.py
COPY bench/results.json ./bench/results.json
COPY --from=ui /ui/dist ./ui/dist
USER ulpf
VOLUME ["/data"]
EXPOSE 8080 5140/udp 5140/tcp
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys;urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health',timeout=2)" || exit 1
ENTRYPOINT ["ulpf"]
CMD ["run", "--workers", "2"]
