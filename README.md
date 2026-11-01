# SBOM Sleuth

**An offline inspector for CycloneDX and SPDX JSON Software Bills of Materials.**

SBOM Sleuth helps developers and security learners identify incomplete inventory metadata, duplicate component identities and broken dependency references.

## Features

- Detects CycloneDX JSON and SPDX JSON documents.
- Reports missing versions, declared licenses and package URLs (purls).
- Finds duplicate component identities.
- Validates CycloneDX dependency references and SPDX relationship identifiers.
- Produces deterministic text or JSON reports.
- Uses only the Python standard library; no network access or external service.

## Requirements

Python 3.10+. No third-party dependencies.

## Usage

```bash
python sbom_sleuth.py examples/cyclonedx.json
python sbom_sleuth.py examples/spdx.json --format json
python sbom_sleuth.py examples/cyclonedx.json --strict
```

Exit codes: `0` analysis completed, `1` strict mode found findings, `2` invalid input, unsupported format or unreadable file.

## Supported formats

- **CycloneDX JSON:** `bomFormat`, `components`, `dependencies`, `bom-ref`, `purl`, `version`, `licenses`.
- **SPDX JSON:** `spdxVersion`, `packages`, `SPDXID`, `versionInfo`, `licenseDeclared`, `externalRefs`, `relationships`.

XML and SPDX tag-value serializations are not currently supported.

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the test suite on pushes and pull requests.

## Safety and limitations

- Reads only the file supplied by the user.
- Makes no network requests and never installs or executes listed components.
- Does not query vulnerability databases, inspect package contents, verify signatures/provenance or determine exploitability.
- Missing license metadata does not prove a component is unlicensed.
- Findings are inventory-quality signals requiring human review.

See [docs/rules.md](docs/rules.md) and [examples](examples/).

## License

MIT.
