# OTel attribute contract v1 (observability)

File: `traigent_schema/data/observability/otel_attribute_contract_v1.json`. Shared by the Backend OTLP
receiver and the Python/JS SDK exporters. Consumers vendor the file and pin its sha256 (this repo pins it in
`tests/test_observability_otel_attribute_contract.py`).

Contents: content-mode declaration (`traigent.content_mode.v1`), content-bearing keys, typed bounded metadata
allowlist (no wildcards), usage classes, observation-type mapping, and the OpenInference vs GenAI precedence
table with executable vectors. Only attribute names are taken from external sources.

## Provenance (names only, no text or code copied)

| Source | URL | Version / date | Purpose | Covered by |
|---|---|---|---|---|
| OpenTelemetry GenAI semantic conventions | https://github.com/open-telemetry/semantic-conventions-genai | commit bcc7f9c2, Development status; fetched 2026-09-30 | attribute names for interoperability | test_observability_otel_attribute_contract.py |
| OpenInference semantic conventions | https://github.com/Arize-ai/openinference/blob/main/spec/semantic_conventions.md | main, 2026-09-30 | attribute and span-kind names for interoperability | same |
| OTLP specification | https://opentelemetry.io/docs/specs/otlp/ | 1.x | wire format (receiver only) | Backend tests |

## Explicit observation type

`traigent.observation_type` (metadata allowlist, string, max 32) lets Traigent SDKs state the observation type
directly. It is checked first: a value that is exactly a member of the Traigent observation type enum
(`observation_ingest_schema.json` `_ObservationType`, mirrored in `observation_type_mapping.explicit_attribute.allowed_values`)
wins over `gen_ai.operation.name`, `openinference.span.kind` and the fallbacks. Absent, non-string, empty or
unlisted values are ignored and the existing mapping applies; they are never an error. Executable vectors live in
`observation_type_mapping.vectors`.

Content policy this round: the receiver drops all content keys whatever the declared mode; the declaration never
grants permission. Storing content requires a future authenticated project policy (owner decision).
