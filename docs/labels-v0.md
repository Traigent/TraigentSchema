# Label service contract (v0, additive)

Phase 2 of the content-less optimization design. Names (labels, knob names, choices, metric
names, templates) never reach Traigent in readable form: writers seal them to a project key,
the service stores ciphertext, and only an approved member's browser decrypts. This note is the
short wire-level reference; the schemas under `traigent_schema/schemas/labels/` are the contract
and `traigent_schema/data/label_vectors_v0.json` are the conformance vectors. Nothing existing
was changed or removed.

| Schema | What it carries |
|---|---|
| `label_common_schema.json` | opaque refs (tenant, project, object, knob, choice, metric, agent, dataset, evaluation set, evaluator), key ids, key material encodings, `ConfigRefMap`, `MetricValueMap` |
| `label_envelope_schema.json` | the sealed label |
| `label_key_binding_schema.json` | signed bindings (admin identity, project key per epoch, member key) and the signed revocation list |
| `label_member_key_schema.json` | member key registration and admin approval |
| `label_wrap_schema.json` | member wrap (flow b), recovery wrap (flow c) |
| `label_local_protection_schema.json` | local protection metadata (flow a) |
| `label_io_schema.json` | write request/response, read response, list |
| `label_epoch_schema.json` | epoch and rotation records |

## Envelope

HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, single-shot.
Packed form `version(1) || key_epoch(4, big-endian) || enc(32) || ciphertext`; the JSON form carries
the same four parts, binary parts as unpadded base64url. Plaintext is UTF-8, padded ISO/IEC 7816-4
(`0x80` then zeros) to 32/64/128/256 bytes (smallest bucket that fits; more than 255 bytes is
refused; malformed or non-minimal padding is refused), so the ciphertext is 48/80/144/272 bytes.
Length is narrowed to a bucket, not hidden.

AAD is not transmitted. Both sides rebuild the RFC 8785 canonical JSON of
`{schema_version, tenant_ref, project_ref, purpose, object_ref, key_epoch, revision}`; HPKE `info`
is the ASCII string `traigent.label.v1`. A write carries `base_revision` (last-seen, 0 to create)
and `epoch`; the new revision is `base_revision + 1`. The object content `revision` is bound into
the AAD (design v2.2 section 3.6): the envelope has no revision field of its own, a writer seals
under the new revision, and a reader opens under the revision it requested, so a ciphertext cannot be
replayed under another revision. Readers also reject any revision below their locally retained
per-object maximum; storage rollback against a reader with no prior state is outside the v1 guarantee.

## Keys and signatures

* Project X25519 key pair per epoch; per-user X25519 member keys; Ed25519 tenant root and admin
  identity keys. `key_id` = first 16 bytes of SHA-256(raw public key), base64url.
* The root fingerprint (SHA-256 of the raw root public key, hex) is pinned outside Traigent and has
  no binding. Binding signature = Ed25519 over `traigent.label.binding.v1\0 || JCS(other fields)`.
  Chain: root -> `admin_identity` (tenant-wide: `project_ref` and `epoch` null) -> `project_key`
  (epoch) and `member_key`. Clients verify the chain before encrypting, wrapping or unwrapping.
  Verification also takes the root-signed `KeyBindingList` and refuses: a list whose `sequence` is
  below the one the client retained (rollback), any key in the chain (or its signer) listed in
  `revoked_key_ids` (a retired admin cannot sign new project or member keys), and any binding whose
  `not_before` is later than the verifier's clock (`verify_chain` in `scripts/labels_reference.py`). `verify_chain` now requires `binding_list`,
  `retained_sequence` and `now`; it is a reference script with no external callers, so the
  signature change is intentional.
* Member keys are trusted only through an admin-signed `member_key` binding. A registration carries
  no self-signature (the schema has no field for one): the approving admin checks the key
  fingerprint with the member out-of-band (read aloud or compared in both UIs) before signing, and
  until then the key is `pending` and nothing is wrapped or encrypted to it.
* Flow (b): project private key sealed (HPKE, same suite) to the member's verified public key,
  `info` = JCS `{tenant_ref, project_ref, epoch, recipient_key_id, purpose:"member_wrap", version}`.
* Flow (c): recovery wrap key = HKDF-SHA256(recovery secret, info `traigent.label.recovery.v1`),
  AES-256-GCM, random nonce, AAD = JCS `{tenant_ref, project_ref, epoch, subject,
  purpose:"recovery_wrap", version}` with `subject` one of `root_key` / `project_key`, so a wrap of one
  kind cannot be replayed as the other. The tenant root key uses the reserved epoch 0.
* Flow (a): wrapping key = HKDF-SHA256(PRF output or Argon2id output, info `traigent.label.local.v1`),
  AES-256-GCM, AAD = JCS `{tenant_ref, member_key_id, purpose:"local_member_key", version}`. The
  metadata schema has no field for a PRF output, passphrase or wrapping key, by design.

## Reference formats

Formats follow the Backend, not a new scheme. Tenant and project refs are the Backend's tenant and
project ids, `tenant_<32 lowercase hex>` and `project_<32 lowercase hex>` (the defaults in `src/models/enterprise_tenant.py` and `src/models/project.py`). Every other ref is `<kind>ref_<32 lowercase hex>`, the
convention of `_new_id(prefix)` in `pillar_legend_service.py` and `opaque_ref()` in
`src/services/director/opaque_ref.py`: `knobref_`, `choiceref_`, `metricref_`, `agentref_`,
`datasetref_`, `evaluationsetref_`, `evaluatorref_`, `cursorref_`; an `ObjectRef` is any of the
object kinds (also `templateref_`). The Backend does not mint knob, choice or metric refs yet; this
contract fixes the format they must use. `KeyId` is derived from the key (first 16 bytes of
SHA-256, base64url). Public keys, signatures, salts, nonces and credential ids are class
`key_material` (base64url, bounded), not `digest`.

## Opaque identity (alongside legacy fields)

Optional, `opaque_ref`-classed fields were added next to the legacy ones, which keep their
`legacy_content` class: session create `agent_ref`, `dataset_ref`, `evaluation_set_ref`,
`evaluator_ref`, `knob_refs`, `choice_refs`, `metric_refs`, `default_config_refs`; next-trial
`trial.config_refs`; submit-results `config_refs`, `metric_values`; finalize `best_config_refs`,
`best_metric_values`; intermediate report `objective_ref`; best config v2 `config_refs`. Existing
`required` entries are untouched, so a content-less client still has to satisfy them (retired in P3, when
the legacy fields are removed).

## Conformance

`scripts/labels_reference.py` is a test-only reference (the installed `cryptography` has no HPKE).
It is proven against the RFC 9180 Appendix A.1 and A.2 X25519 base-mode vectors
(`tests/data/rfc9180_x25519_base_vectors.json`); AES-256 differs from A.1 only in the key length.
Regenerate vectors with `python3 scripts/generate_label_vectors.py --update`; all keys in them are
derived from a public constant and protect nothing. Tests: `tests/test_labels_vectors.py`.
