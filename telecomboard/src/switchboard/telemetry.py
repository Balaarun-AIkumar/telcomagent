"""One instrumentation path: OTel when installed/configured, always a scrubbed in-process span log for tests."""
from __future__ import annotations

import hashlib
import os
from base64 import b64encode
from collections import Counter, deque
from contextlib import contextmanager

from .context import current_trace_id
from .redaction import mask_pii, scrub

SPAN_LOG: deque[dict] = deque(maxlen=5000)
METRICS: Counter = Counter()
_tracer = None


def setup(service_name: str, app=None) -> None:
    """Export via generic OTLP or Langfuse; SB_OTEL_CONSOLE=1 prints spans."""
    global _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
    except ImportError:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    langfuse_base = os.getenv("LANGFUSE_BASE_URL")
    langfuse_endpoint = os.getenv("LANGFUSE_OTLP_ENDPOINT")
    if not langfuse_endpoint and langfuse_base and (public_key or secret_key):
        langfuse_endpoint = langfuse_base.rstrip("/") + "/api/public/otel/v1/traces"
    if langfuse_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        basic_auth = os.getenv("LANGFUSE_BASIC_AUTH")
        if not basic_auth and public_key and secret_key:
            basic_auth = b64encode(f"{public_key}:{secret_key}".encode()).decode()
        if not basic_auth:
            raise RuntimeError("Langfuse public/secret keys or LANGFUSE_BASIC_AUTH are required")
        authorization = basic_auth if basic_auth.lower().startswith("basic ") else f"Basic {basic_auth}"
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(
            endpoint=langfuse_endpoint,
            headers={"Authorization": authorization, "x-langfuse-ingestion-version": "4"},
        )))
    elif os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    if os.getenv("SB_OTEL_CONSOLE") == "1":
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("switchboard")
    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz")
        except ImportError:
            pass


def adopt_traceparent(header: str | None) -> None:
    """Continue the caller's W3C trace so downstream spans share one trace_id."""
    parts = (header or "").split("-")
    if len(parts) == 4 and len(parts[1]) == 32 and all(c in "0123456789abcdef" for c in parts[1]):
        current_trace_id.set(parts[1])


def pseudo_id(user_id: str) -> str:
    salt = os.getenv("SB_PSEUDO_SALT", "dev-salt")
    return hashlib.sha256(f"{salt}:{user_id}".encode()).hexdigest()[:16]


def _clean(v: object) -> str | int | float | bool:
    if isinstance(v, (int, float, bool)):
        return v
    return mask_pii(scrub(str(v)))[:2000]


@contextmanager
def span(name: str, **attrs):
    clean = {k: _clean(v) for k, v in attrs.items() if v is not None}
    rec = {"name": name, "trace_id": current_trace_id.get(), "attrs": clean}
    SPAN_LOG.append(rec)
    if _tracer is None:
        yield rec
        return
    with _tracer.start_as_current_span(name, attributes=clean) as s:
        rec["trace_id"] = f"{s.get_span_context().trace_id:032x}"
        token = current_trace_id.set(rec["trace_id"])
        try:
            yield rec
        finally:
            for k, v in rec["attrs"].items():
                s.set_attribute(k, _clean(v))
            current_trace_id.reset(token)


def set_attr(rec: dict, key: str, value: object) -> None:
    rec["attrs"][key] = _clean(value)


def incr(metric: str, n: int = 1) -> None:
    METRICS[metric] += n
