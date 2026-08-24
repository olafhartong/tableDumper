# BloodHound and OpenGraph

The OpenGraph flags can generate BloodHound-compatible graph artifacts, upload an existing graph, and create or update custom node icons. For the precise accepted row shapes and property normalization rules, also see the existing [OpenGraph format reference](../opengraph.md).

## `--opengraph-export`

Converts graph-shaped Defender query results into:

- `<base>.opengraph.json`: an OpenGraph payload containing nodes and/or edges
- `<base>.opengraph.icons.json`: a custom-node icon payload when exported kinds are present

```bash
./tableDumper \
  --auth azcli \
  --query-file alertOpenGraph.kql \
  --output alerts.json \
  --opengraph-export
```

The exporter recognizes the supported Alert-style and ExposureGraph-style node and edge shapes. It rejects unrelated tabular data instead of guessing. Nested properties are normalized for BloodHound, and edge-only ExposureGraph rows can synthesize endpoint nodes when enough metadata is available.

The flag works with non-partitioned query results and non-partitioned table dumps. It is rejected when either result reaches `--dump-row-limit` (or Defender's byte-size limit) and becomes partitioned, because graph construction requires the complete result set in memory.

If pseudonymization is enabled, OpenGraph is built from the pseudonymized rows. The generated graph is generic OpenGraph: it can be imported and queried with Cypher, but arbitrary relationships do not automatically gain BloodHound Pathfinding semantics.

## `--bloodhound-url`

Sets the BloodHound base URL. Environment variable: `BLOODHOUND_URL`.

```text
https://your-tenant.bloodhoundenterprise.io
```

It is required whenever one of the BloodHound upload flags is used. A trailing slash is removed automatically. It is not needed merely to generate local OpenGraph files.

## BloodHound authentication flags

### `--bloodhound-token`

Uses a JWT bearer token. Environment variable: `BLOODHOUND_TOKEN`.

### `--bloodhound-token-id`

Sets the API token ID for BloodHound signed requests. Environment variable: `BLOODHOUND_TOKEN_ID`.

### `--bloodhound-token-key`

Sets the Base64-encoded API token key used to HMAC-sign requests. Environment variable: `BLOODHOUND_TOKEN_KEY`.

Every upload requires either the bearer token or both signed-token values. Supplying only one member of the ID/key pair is an error. If both bearer and signed credentials are supplied, the bearer token takes precedence.

Treat all token values as secrets. Prefer process environment or a protected dotenv file over command-line arguments.

## `--bloodhound-upload-generated`

Uploads both artifacts produced by the current `--opengraph-export` operation:

1. The graph file is sent through BloodHound's file-upload job API.
2. The icon file is sent through the custom-node API when an icon sidecar was generated.

```bash
./tableDumper \
  --auth azcli \
  --query-file alertOpenGraph.kql \
  --output alerts.json \
  --opengraph-export \
  --bloodhound-url "$BLOODHOUND_URL" \
  --bloodhound-token-id "$BLOODHOUND_TOKEN_ID" \
  --bloodhound-token-key "$BLOODHOUND_TOKEN_KEY" \
  --bloodhound-upload-generated
```

This flag requires `--opengraph-export` and specifically requires `--query` or `--query-file`. It cannot upload generated output from `--dump-table`, even when that dump would be small enough for OpenGraph export.

## `--bloodhound-upload-file`

Uploads an existing OpenGraph JSON or ZIP file using BloodHound's start/upload/end file-job sequence.

```bash
./tableDumper \
  --bloodhound-url "$BLOODHOUND_URL" \
  --bloodhound-token "$BLOODHOUND_TOKEN" \
  --bloodhound-upload-file alerts.opengraph.json
```

Files ending in `.zip` are sent as `application/zip`; other extensions are sent as JSON. This action is independent of query collection and does not require `--opengraph-export`.

## `--bloodhound-upload-icons-file`

Loads an existing custom-node payload and applies it to BloodHound.

```bash
./tableDumper \
  --bloodhound-url "$BLOODHOUND_URL" \
  --bloodhound-token-id "$BLOODHOUND_TOKEN_ID" \
  --bloodhound-token-key "$BLOODHOUND_TOKEN_KEY" \
  --bloodhound-upload-icons-file alerts.opengraph.icons.json
```

The JSON must contain a non-empty `custom_types` object. The operation is idempotent at the kind level:

- missing kinds are created
- existing kinds are updated

This action can run alone, alongside `--bloodhound-upload-file`, or after another action in the same invocation.

## Uploading existing graph and icons together

```bash
./tableDumper \
  --bloodhound-url "$BLOODHOUND_URL" \
  --bloodhound-token-id "$BLOODHOUND_TOKEN_ID" \
  --bloodhound-token-key "$BLOODHOUND_TOKEN_KEY" \
  --bloodhound-upload-file alerts.opengraph.json \
  --bloodhound-upload-icons-file alerts.opengraph.icons.json
```

Use `--timeout` to allow more time for large uploads. `--insecure-skip-verify` also affects BloodHound connections, but should be limited to controlled systems with an intentionally untrusted certificate.
