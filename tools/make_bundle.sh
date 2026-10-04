#!/usr/bin/env bash
# Build dist/ulpf-offline-<ver>.tar.gz on an ONLINE machine (§10):
#   docker save images (ulpf, redis, optional opensearch/ollama) + compose files + sample data + SHA256SUMS + install.sh
# Usage: tools/make_bundle.sh [--with-siem] [--with-ai] [--skip-build]
set -euo pipefail
cd "$(dirname "$0")/.."
VER="${ULPF_VERSION:-$(sed -n 's/^version *= *"\(.*\)"/\1/p' pyproject.toml | head -1)}"
VER="${VER:-dev}"
WITH_SIEM=0; WITH_AI=0; BUILD=1
for a in "$@"; do case "$a" in --with-siem) WITH_SIEM=1;; --with-ai) WITH_AI=1;; --skip-build) BUILD=0;; *) echo "unknown arg $a" >&2; exit 2;; esac; done
command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }

STAGE="dist/ulpf-offline-$VER"
rm -rf "$STAGE"; mkdir -p "$STAGE/images" "$STAGE/docker" "$STAGE/sample" "$STAGE/configs" "$STAGE/secrets"

export ULPF_VERSION="$VER"
FILES=(-f docker/compose.yml); IMAGES=("ulpf:$VER" "redis:7-alpine")
[ $WITH_SIEM = 1 ] && { FILES+=(-f docker/compose.siem.yml); IMAGES+=("opensearchproject/opensearch:2.15.0" "opensearchproject/opensearch-dashboards:2.15.0"); }
[ $WITH_AI = 1 ] && { FILES+=(-f docker/compose.ai.yml); IMAGES+=("ollama/ollama:latest"); }

# Wheels are resolved inside the image build (docker/Dockerfile `wheels` stage, from the committed requirements.lock) so they always match the
# image's Python. Do not pre-fill ./wheelhouse from the host: a host Python of another minor version would produce incompatible wheels.
[ -f requirements.lock ] || { echo "requirements.lock missing (uv pip compile pyproject.toml -o requirements.lock)" >&2; exit 1; }
if [ $BUILD = 1 ]; then
  docker compose "${FILES[@]}" build
fi
for img in "${IMAGES[@]}"; do docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"; done
docker save "${IMAGES[@]}" | gzip -9 > "$STAGE/images/images.tar.gz"

cp docker/compose*.yml "$STAGE/docker/"
cp configs/ulpf.yaml "$STAGE/configs/"
# deterministic sample data (generated truth is separate from public data, see tools/loggen/import_public.md)
PYTHONPATH=src:. python3 -m tools.loggen --scenario tools/loggen/scenarios/demo.yaml --duration 300 --eps 200 --out "$STAGE/sample/demo.log" >/dev/null
cp tools/loggen/scenarios/demo.yaml "$STAGE/sample/"
[ -d docs ] && cp -r docs "$STAGE/docs"
printf '%s\n' "$VER" > "$STAGE/VERSION"
printf '%s\n' "${FILES[*]}" > "$STAGE/.compose-files"

cat > "$STAGE/install.sh" <<'INST'
#!/usr/bin/env bash
# Offline install: verify checksums, docker load, compose up. No network access is required or attempted.
set -euo pipefail
cd "$(dirname "$0")"
sha256sum -c SHA256SUMS --quiet
gunzip -c images/images.tar.gz | docker load
[ -f secrets/ulpf_ed25519 ] || echo "note: no signing key in ./secrets/ulpf_ed25519 - generate one (see docs/lineage-spec.md) before ingesting" >&2
export ULPF_VERSION="$(cat VERSION)"
docker compose $(cat .compose-files) up -d
echo "ULPF is starting. UI: http://127.0.0.1:8080"
INST
chmod +x "$STAGE/install.sh"

( cd "$STAGE" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS )
tar -C dist -czf "dist/ulpf-offline-$VER.tar.gz" "ulpf-offline-$VER"
( cd dist && sha256sum "ulpf-offline-$VER.tar.gz" > "ulpf-offline-$VER.tar.gz.sha256" )
echo "bundle: dist/ulpf-offline-$VER.tar.gz"
