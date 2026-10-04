PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python)
BIN := $(dir $(PY))
.PHONY: dev verify test lint type demo bench bundle airgap-test ui ui-smoke docs
dev:
	uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev,fast]"
verify: lint type test
lint:
	$(PY) -m ruff check src tests
type:
	$(PY) -m mypy --strict src/ulpf/model src/ulpf/vault src/ulpf/packs
test:
	$(PY) -m pytest tests
demo:
	$(BIN)ulpf demo
bench:
	$(BIN)ulpf bench
bundle:
	bash tools/make_bundle.sh
airgap-test:
	bash tools/airgap_test.sh
ui:
	cd ui && pnpm install --frozen-lockfile && pnpm build
ui-smoke:
	ULPF_PY=$(abspath $(PY)) node ui/scripts/smoke.mjs
docs:
	@echo "docs live in docs/"
