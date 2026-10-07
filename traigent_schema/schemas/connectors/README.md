# Connector summary schemas

- These schemas are closed: every object sets `additionalProperties: false`.
- Any new field or enum value is a new `schema_version`, published alongside the old one.
- Consumers dispatch on `schema_version`; the `$id` carries the matching version segment (`/connectors/v1/`).
