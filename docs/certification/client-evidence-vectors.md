# Client-local evidence construction: known-answer vectors (G1)

Status: normative vectors for text that already exists in the schemas. No schema JSON is
changed by this note.

| Artifact | Path |
|---|---|
| Normative text (slot commitment) | `traigent_schema/schemas/certification/certification_common_v0_schema.json` `CommitmentSchemeV0` |
| Normative text (root digest domain) | same file, `DigestRoleDomainTagV0` and `CanonicalizationProfileV0` |
| Manifest wire shape | `traigent_schema/schemas/certification/certificate_client_evidence_manifest_v0_schema.json` |
| Canonicalization reference | `traigent_schema/fp2.py`, `docs/fingerprints/fp2.md` |
| Vectors | `tests/data/client_evidence_kats.json` |
| Test (recomputes every vector from the text, imports no SDK and not `fp2`) | `tests/test_client_evidence_vectors.py` |

## Construction

For each of the four fixed slots (`agent_revision`, `evaluation_dataset`, `evaluator`,
`build_process_evidence`):

    slot_commitment_digest = "sha256:" + hex(HMAC-SHA-256(
        key  = blind,                                  # exactly 32 bytes, per slot, client-local
        data = UTF8("traigent.cert.v0.slot_commitment.v1") || 0x00
               || UTF8(artifact_kind) || 0x00
               || jcs_v1(artifact_document)))

The manifest is the closed object `{schema_version, agent_revision, evaluation_dataset,
evaluator, build_process_evidence}`; each slot is `{artifact_kind, commitment_scheme:
"sha256_secret_blinded_v1", slot_commitment_digest}`. The root that crosses the Backend
boundary (claim G1 `manifest_root_digest`) is:

    "sha256:" + hex(SHA-256(UTF8("traigent.agent_certificate.client_evidence_manifest_root.v1")
                            || 0x00 || jcs_v1(manifest)))

`jcs_v1` is RFC 8785 with floats banned: any float, non-finite number, integer beyond
2^53-1 or lone surrogate in an `artifact_document` MUST be refused before hashing. A blind
that is not exactly 32 bytes MUST be refused.

## Slot document for `build_process_evidence`

Digest-only and float-free: `{"snapshot_format": "tes1", "manifest_digest": "sha256:<64 hex>"}`.
The other three slot documents are producer-defined, client-local JSON objects; the vectors
use illustrative digest-only documents and pin the arithmetic, not their field names.

## Vector file

`slot_cases` (blind as hex, kind, document, expected JCS text, expected digest, including
key ordering, UTF-16 ordering of astral keys, string escapes and integer bounds),
`manifests` (a full four-slot manifest with expected root), `build_process_evidence`, and
`negative_cases` (float, unsafe integer, wrong blind length, unknown kind: all MUST be
rejected). Independent implementations should reproduce every positive digest and reject
every negative case.
