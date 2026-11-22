.PHONY: up down lint typecheck test test-personas benchmark demo verify-trace verify-all

up:
	docker compose up -d --wait postgres

down:
	docker compose down -v

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy src tests benchmarks examples

test:
	uv run pytest -q tests/test_components.py tests/test_mcp_protocol.py

test-personas:
	uv run pytest -q -s tests/test_personas.py

benchmark:
	uv run python benchmarks/run_benchmark.py --check

demo:
	GATEKEEPER_TRACE_DIR=traces/demo uv run python examples/demo.py

# Generate a real trace with the demo, then verify its hash chain.
verify-trace: demo
	uv run mcp-gatekeeper verify-trace "$$(ls -t traces/demo/*.jsonl | head -1)"

verify-all: lint typecheck test test-personas benchmark verify-trace
