# Rule reference

| ID | Severity | Meaning |
|---|---|---|
| SB000 | high | A component/package entry is not an object. |
| SB001 | high | Version metadata is missing. |
| SB002 | medium | Declared license metadata is missing or unknown. |
| SB003 | medium | Package URL (purl) is missing. |
| SB004 | medium | Duplicate component identity. |
| SB005 | high | A dependency or relationship references an undeclared identifier. |

Missing license metadata does not mean a package is unlicensed. Missing purl makes matching harder but does not imply maliciousness. Duplicate names may be legitimate if metadata is incomplete. Reference checks validate document-internal identifiers only.

This tool does not query vulnerability databases, inspect package contents, verify signatures/provenance, or determine exploitability. Results are inventory-quality signals for human review.
