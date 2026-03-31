"""Integration tests for logging, instrumentation, and cross-module consistency."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

import io
import json
import logging

# ---------------------------------------------------------------------------
# Logging with session_id
# ---------------------------------------------------------------------------


class TestLoggingSetup:
    """Verify setup_logging() behaviour and session_id injection."""

    def _reset_logging(self):
        """Remove all handlers and reset the idempotency guard for test isolation."""
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        import logging_config
        logging_config._configured = False

    def test_setup_logging_is_idempotent(self):
        """Calling setup_logging() twice must not add a second handler."""
        from logging_config import setup_logging

        self._reset_logging()
        setup_logging()
        setup_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1, (
            f"Expected 1 handler after two setup_logging() calls, got {len(root.handlers)}"
        )

    def test_log_output_contains_session_id_when_set(self):
        """When session_id_var is set, JSON log lines must include 'session_id'."""
        from logging_config import session_id_var, setup_logging

        self._reset_logging()
        setup_logging()

        # Redirect the root handler's stream to a StringIO buffer
        root = logging.getLogger()
        buf = io.StringIO()
        for handler in root.handlers:
            if hasattr(handler, "stream"):
                handler.stream = buf

        token = session_id_var.set("test-session-42")
        try:
            logging.getLogger("honeypot.test").info("hello with session")
            output = buf.getvalue()
            record = json.loads(output.strip().splitlines()[-1])
            assert record.get("session_id") == "test-session-42", (
                f"session_id not found or wrong in log record: {record}"
            )
        finally:
            session_id_var.reset(token)

    def test_log_output_omits_session_id_when_unset(self):
        """When session_id_var has no value, 'session_id' should be absent from the log."""
        from logging_config import setup_logging

        self._reset_logging()
        setup_logging()

        root = logging.getLogger()
        buf = io.StringIO()
        for handler in root.handlers:
            if hasattr(handler, "stream"):
                handler.stream = buf

        # Ensure session_id_var has no value (default)
        # contextvars default is typically empty/unset
        logging.getLogger("honeypot.test").info("hello without session")
        output = buf.getvalue()
        if output.strip():
            record = json.loads(output.strip().splitlines()[-1])
            assert "session_id" not in record, (
                f"session_id should be absent but found: {record}"
            )


# ---------------------------------------------------------------------------
# Instrumentation idempotency
# ---------------------------------------------------------------------------


class TestInstrumentation:
    """Verify telemetry setup and tracer creation."""

    def test_setup_telemetry_idempotent(self):
        """Calling setup_telemetry() twice must not raise and must leave flag True."""
        from instrumentation import setup_telemetry

        setup_telemetry()
        setup_telemetry()  # second call should be a no-op
        # Re-import to pick up the current module-level value
        import instrumentation
        assert instrumentation._telemetry_initialised is True

    def test_get_tracer_returns_tracer_object(self):
        """get_tracer() must return a real Tracer, not None."""
        from instrumentation import get_tracer, setup_telemetry

        setup_telemetry()
        tracer = get_tracer("test")
        assert tracer is not None, "get_tracer('test') returned None"
        # The object should have a start_span method (duck-type check)
        assert hasattr(tracer, "start_span"), (
            f"Tracer object missing start_span: {type(tracer)}"
        )
