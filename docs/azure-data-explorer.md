# Azure Data Explorer

The ADX flags support two separate workflows:

1. `--adx-export` creates local ingestion artifacts from a Defender query or table dump. It does not contact ADX.
2. `--adx-upload-file` connects to ADX, prepares the table and JSON mapping, and ingests an existing file in batches.

The workflows can be used independently or chained across separate commands.

## `--adx-export`

Generates two sidecars next to `--output`:

- `<base>.adx.json`: newline-delimited JSON with one result row per line
- `<base>.adx.kql`: KQL management commands for the table and JSON ingestion mapping

```bash
./tableDumper \
  --auth azcli \
  --query-file queries/events.kql \
  --output events.json \
  --adx-export \
  --adx-table DefenderEvents
```

Export requires query or table-dump results with a usable schema. When the Graph response has no schema, the tool attempts to infer it from returned rows. `--adx-cluster` and `--adx-database` are not needed because no upload occurs.

For partitioned queries and table dumps, the NDJSON sidecar is streamed with the main output. If pseudonymization is enabled, both the main output and ADX data sidecar contain pseudonymized values.

## `--adx-cluster`

Sets the ADX engine-cluster URI used by direct upload. Environment variable: `ADX_CLUSTER`.

```text
https://yourcluster.westeurope.kusto.windows.net
```

It is required with `--adx-upload-file`. A trailing slash is removed automatically. Use the engine cluster URI, not a database name or an arbitrary ingestion file URL.

## `--adx-database`

Sets the destination ADX database. Environment variable: `ADX_DATABASE`. It is required with `--adx-upload-file`.

The authenticated identity must be allowed to execute the management, mapping, and ingestion commands used by the tool in this database.

## `--adx-table`

Sets the ADX table name.

- With `--adx-upload-file`, it is required.
- With `--adx-export`, it is optional; the tool derives a safe name from the main output filename when omitted.

The value must be a safe ADX identifier: letters or underscore first, followed by letters, digits, or underscores.

For direct upload, the tool checks the destination and creates the table when it does not exist. The source schema comes from the Defender response or is inferred from the input rows.

## `--adx-mapping`

Sets the name of the JSON ingestion mapping used in generated KQL and direct upload. When omitted, it defaults to `<table>_json`.

The value must be a safe ADX identifier. During direct upload, the mapping is created or updated to match the source schema.

## `--adx-upload-file`

Starts direct ADX upload mode for the selected path.

Supported input shapes:

1. A Defender response object containing `Schema` and `Results`
2. A JSON array of row objects
3. One JSON row object
4. Newline-delimited JSON, one object per non-empty line

```bash
./tableDumper \
  --auth sp \
  --adx-cluster 'https://yourcluster.westeurope.kusto.windows.net' \
  --adx-database SecurityData \
  --adx-table DefenderEvents \
  --adx-upload-file events.adx.json
```

This action requires `--adx-cluster`, `--adx-database`, and `--adx-table`. It does not require `--query`, `--dump-table`, `--output`, or `--adx-export`.

The tool reads the file, determines its schema, ensures the table and mapping exist, then uses ADX inline ingestion commands in batches. An empty file without schema cannot be uploaded. Pseudonymization is a collection-time feature and is not applied to `--adx-upload-file`; pseudonymize the source during collection or beforehand.

## `--adx-batch-size`

Sets the number of rows placed in each ADX ingestion request. Default: `500`; it must be greater than zero.

Smaller batches reduce individual request size and make failures more localized, at the cost of more management requests. Larger batches reduce request count but use more memory and can create larger inline command payloads.

The flag is parsed for every invocation but only affects `--adx-upload-file`.

## ADX authentication flags

### `--adx-tenant-id`

Sets the Microsoft Entra tenant used to obtain an ADX token. Environment variable: `ADX_TENANT_ID`.

### `--adx-client-id`

Sets the service-principal application/client ID used for ADX. Environment variable: `ADX_CLIENT_ID`.

### `--adx-client-secret`

Sets the service-principal secret used for ADX. Environment variable: `ADX_CLIENT_SECRET`.

These credentials are intentionally separate from `--tenant-id`, `--client-id`, and `--client-secret`, which belong to Defender/Graph. With `--auth sp`, all three ADX values are required for direct upload. With `--auth auto`, a complete ADX credential set selects service-principal authentication; otherwise the tool uses Azure CLI.

For an ADX-compatible endpoint that intentionally allows anonymous requests, use `--adx-auth none`. This skips ADX token acquisition and sends no `Authorization` header while leaving the general `--auth` mode available for Defender/Graph collection. When `--adx-auth` is omitted, ADX inherits `--auth`. Both `http://` and `https://` cluster URLs are accepted; use plain HTTP only on a trusted network because the uploaded data is not encrypted in transit. Environment variable: `ADX_AUTH`.

```bash
./tableDumper \
  --adx-auth none \
  --adx-cluster 'http://localhost:8080' \
  --adx-database SecurityData \
  --adx-table DefenderEvents \
  --adx-upload-file events.adx.json
```

To collect from Defender, pseudonymize, and upload to anonymous ADX in one invocation, enable the ADX sidecar and select that generated file for upload:

```bash
./tableDumper \
  --auth azcli \
  --adx-auth none \
  --query-file exampleQueries/DeviceProcessEvents.kql \
  --output device-process-events.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --adx-export \
  --adx-cluster 'http://10.93.40.236:8080' \
  --adx-database SecurityData \
  --adx-table DeviceProcessEvents \
  --adx-upload-file device-process-events.adx.json
```

Prefer environment or protected dotenv values for the secret rather than a command-line argument.

## `--adx-resource`

Sets the OAuth audience for ADX tokens. Environment variable: `ADX_RESOURCE`. Default when neither the flag nor environment supplies a value: `https://api.kusto.windows.net`.

The value is used for both service-principal and Azure CLI token acquisition. Override it only when the ADX environment requires a different audience.

## End-to-end export and upload

Collect and create artifacts:

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceInfo \
  --output devices.json \
  --adx-export \
  --adx-table DeviceInventory
```

Upload the resulting NDJSON:

```bash
./tableDumper \
  --auth azcli \
  --adx-cluster "$ADX_CLUSTER" \
  --adx-database SecurityData \
  --adx-table DeviceInventory \
  --adx-upload-file devices.adx.json \
  --adx-batch-size 500
```
