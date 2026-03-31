# Examples

Runnable examples showing how to connect to the MCP honeypot, test agents,
and wire up the telemetry pipeline for validation.

## Prerequisites

All examples require the Docker Compose stack running:

```bash
docker compose up --build -d
```

And httpx installed:

```bash
pip install httpx
```

## Files

| Example | What it demonstrates |
|---------|---------------------|
| `basic_client.py` | Minimal MCP client — connect, initialize, call one tool |
| `multi_session.py` | Multiple concurrent agent sessions with different fingerprints |
| `flag_triggers.py` | Trigger each of the 7 anomaly flags with minimal code |
| `telemetry_check.py` | Query Jaeger + Prometheus to verify the pipeline works |
| `custom_agent.py` | Build your own attack agent with configurable behavior |
| `pytest_integration.py` | Use the test harness in a pytest test |
