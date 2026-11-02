These schemas were downloaded from the official CycloneDX schema service:

- https://cyclonedx.org/schema/bom-1.6.schema.json
- https://cyclonedx.org/schema/spdx.schema.json
- https://cyclonedx.org/schema/jsf-0.82.schema.json

They are vendored for offline runtime and test validation. Their contents are unchanged apart from JSON formatting. The schemas state that they are published under Apache License 2.0; see LICENSE.txt. Ajv validates the complete schema with standard and internationalized string formats. TRACEGUARD additionally validates unique component IDs and dependency referential integrity.
