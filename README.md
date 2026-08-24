# Defender for Endpoint KQL Dumper

Small Go CLI to:

- run a Microsoft Defender XDR advanced hunting query through Microsoft Graph and write the JSON response to disk
- dump a whole Defender XDR advanced hunting table over a lookback window, partitioning large dumps into chunks automatically
- generate Azure Data Explorer ingestion artifacts from those results
- generate a BloodHound OpenGraph JSON payload from graph-shaped Defender results
- upload a JSON file into an Azure Data Explorer table in configurable batches

## What it does

- Runs `POST /security/runHuntingQuery` against the Microsoft Graph security API for Defender XDR advanced hunting
- Authenticates with either:
  - a Microsoft Entra service principal
  - Azure CLI credentials from `az login`
- Writes the API response to a pretty-printed JSON file
- Can dump an entire table by name with a default `30d` lookback
- Counts matching rows before dumping and uses hash-partitioned chunk queries when the result set exceeds `30000` rows
- Optionally writes Azure Data Explorer ingestion artifacts
- Optionally writes a BloodHound OpenGraph JSON payload
- Optionally uploads JSON data into Azure Data Explorer

## Build

```bash
go build -o tableDumper .
```

## Modes

### 1. Query Defender XDR

```bash
./tableDumper \
  --auth azcli \
  --query "DeviceInfo | limit 10" \
  --output results.json
```

### 2. Query Defender and prepare ADX ingestion files

```bash
./tableDumper \
  --auth sp \
  --query-file query.kql \
  --output defender-results.json \
  --adx-export \
  --adx-table DefenderEvents
```

### 3. Dump a whole Defender table

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceEvents \
  --dump-lookback 30d \
  --output device-events.json
```

### 4. Query Defender and prepare a BloodHound OpenGraph file

```bash
./tableDumper \
  --auth azcli \
  --query-file AlertNodes.kql \
  --output alert-nodes.json \
  --opengraph-export
```

### 5. Upload a JSON file to ADX

```bash
./tableDumper \
  --auth sp \
  --adx-cluster "https://yourcluster.westeurope.kusto.windows.net" \
  --adx-database SecurityData \
  --adx-table DefenderEvents \
  --adx-upload-file defender-results.adx.json
```

## Authentication

### Service principal

The tool reads these flags or environment variables. It also loads a `.env` file automatically if one exists.

- `--tenant-id` or `AZURE_TENANT_ID`
- `--client-id` or `AZURE_CLIENT_ID`
- `--client-secret` or `AZURE_CLIENT_SECRET`
- `--adx-tenant-id` or `ADX_TENANT_ID`
- `--adx-client-id` or `ADX_CLIENT_ID`
- `--adx-client-secret` or `ADX_CLIENT_SECRET`

Environment variables from the real shell take precedence over `.env`, and explicit flags take precedence over both.

Example:

```bash
./tableDumper \
  --auth sp \
  --query "DeviceInfo | limit 10" \
  --output results.json
```

Example `.env`:

```bash
AZURE_TENANT_ID="<tenant-id>"
AZURE_CLIENT_ID="<app-id>"
AZURE_CLIENT_SECRET="<client-secret>"
ADX_CLUSTER="https://yourcluster.westeurope.kusto.windows.net"
ADX_DATABASE="SecurityData"
ADX_TENANT_ID="<adx-tenant-id>"
ADX_CLIENT_ID="<adx-app-id>"
ADX_CLIENT_SECRET="<adx-client-secret>"
```

### Azure CLI

Log in first:

```bash
az login
```

Then run:

```bash
./tableDumper \
  --auth azcli \
  --query "DeviceInfo | limit 10" \
  --output results.json
```

Azure CLI is also used for ADX upload mode when `--auth azcli` is selected.

## Query input

Inline query:

```bash
./tableDumper --auth azcli --query "DeviceInfo | limit 10" --output results.json
```

Query from file:

```bash
./tableDumper --auth azcli --query-file query.kql --output results.json
```

## Table dump

Use `--dump-table` to dump all rows from a Defender XDR advanced hunting table over a lookback window. The tool first runs a count query:

```kql
<table>
| where Timestamp >= ago(<lookback>)
| count
```

If the count is below `30000`, it dumps the table directly. If the count is `30000` or higher, it counts hash partitions and then queries each non-empty partition in parallel, streaming each completed chunk to one JSON response file with the usual `Schema` and `Results` fields. Partitioned dumps do not keep the full result set in memory; only the active chunk responses are held while they are written.

When `--adx-export` is used with a partitioned dump, the ADX newline-delimited JSON sidecar is streamed at the same time as the main output file.

`--opengraph-export` is only supported for non-partitioned table dumps because building the OpenGraph payload requires all rows in memory.

During a table dump, progress is written to stderr. It reports the matching row count, partition sizing, and each completed partition chunk. The final summary report is still written to stdout.

Example:

```bash
./tableDumper \
  --auth sp \
  --dump-table DeviceProcessEvents \
  --dump-lookback 14d \
  --dump-parallelism 6 \
  --output device-process-events.json
```

By default, the lookback filter uses the `Timestamp` column. Use `--dump-time-column` only for tables with a different time column.

## Azure Data Explorer export

Use `--adx-export` to generate two extra files alongside the normal API response:

- `<base>.adx.json`: newline-delimited JSON, one result row per line
- `<base>.adx.kql`: KQL commands to create the table schema and JSON ingestion mapping

Example:

```bash
./tableDumper \
  --auth sp \
  --query-file query.kql \
  --output defender-results.json \
  --adx-export \
  --adx-table DefenderEvents
```

This writes:

- `defender-results.json`
- `defender-results.adx.json`
- `defender-results.adx.kql`

If you omit `--adx-table`, the tool derives a safe table name from the output filename. If you omit `--adx-mapping`, it defaults to `<table>_json`.

## BloodHound OpenGraph export

Use `--opengraph-export` to generate an extra file alongside the normal API response:

- `<base>.opengraph.json`: BloodHound OpenGraph payload with `graph.nodes` or `graph.edges`
- `<base>.opengraph.icons.json`: BloodHound custom node icon payload for the exported node kinds

Example:

```bash
./tableDumper \
  --auth azcli \
  --query-file ExposureGraphEdges.adx.kql \
  --output exposure-edges.json \
  --opengraph-export
```

This writes:

- `exposure-edges.json`
- `exposure-edges.opengraph.json`
- `exposure-edges.opengraph.icons.json`

The exporter is intended for graph-shaped query results such as `AlertNodes`, `AlertEdges`, `ExposureGraphNodes`, and `ExposureGraphEdges`. It lowercases property names, flattens nested objects, and sanitizes kinds so the payload can be ingested by BloodHound. It also emits a matching custom-node icon payload that you can upload to BloodHound so non-native kinds render with specific icons. The exact mapping rules and constraints are documented in `opengraph.md`.

You can also return nodes and edges from a single unioned query. The repo includes [alertOpenGraph.kql](/Users/olafhartong/Code/tableDumper/alertOpenGraph.kql) as an example that produces a mixed result set for one-pass OpenGraph export.

This exporter produces generic OpenGraph payloads. Those import correctly and can be queried in BloodHound with Cypher, but they do not participate in the Pathfinding UI. Pathfinding requires a structured OpenGraph extension schema installed in BloodHound and a compatible PostgreSQL-backed deployment.

## BloodHound upload

The CLI can upload OpenGraph artifacts directly to BloodHound using either:

- a BloodHound bearer token
- a BloodHound API token ID/key pair for signed requests

Upload the files generated by the current query:

```bash
./tableDumper \
  --auth azcli \
  --query-file alertOpenGraph.kql \
  --output alerts.json \
  --opengraph-export \
  --bloodhound-url "https://your-tenant.bloodhoundenterprise.io" \
  --bloodhound-token-id "<token-id>" \
  --bloodhound-token-key "<token-key>" \
  --bloodhound-upload-generated
```

Upload existing files:

```bash
./tableDumper \
  --bloodhound-url "https://your-tenant.bloodhoundenterprise.io" \
  --bloodhound-token-id "<token-id>" \
  --bloodhound-token-key "<token-key>" \
  --insecure-skip-verify \
  --bloodhound-upload-file alerts.opengraph.json \
  --bloodhound-upload-icons-file alerts.opengraph.icons.json
```

Use `--insecure-skip-verify` only when you are connecting to an HTTPS endpoint with a self-signed or otherwise untrusted certificate.

## Azure Data Explorer upload

Use `--adx-upload-file` to ingest data into an ADX table. The tool:

- reads a raw Defender response file, a JSON array of objects, or newline-delimited JSON
- creates the target table if it does not already exist
- creates or updates a JSON ingestion mapping
- ingests the file in batches of `500` rows by default using ADX inline ingestion commands

Example:

```bash
./tableDumper \
  --auth sp \
  --adx-cluster "https://yourcluster.westeurope.kusto.windows.net" \
  --adx-database SecurityData \
  --adx-table DefenderEvents \
  --adx-upload-file defender-results.adx.json \
  --adx-batch-size 500
```

Required flags for upload mode:

- `--adx-cluster`
- `--adx-database`
- `--adx-table`
- `--adx-upload-file`

If `--adx-mapping` is omitted, the tool defaults to `<table>_json`.

The upload mode uses the ADX token audience `https://api.kusto.windows.net` by default.

## Command options

`--auth`
- Authentication mode: `auto`, `sp`, or `azcli`
- Default: `auto`

`--tenant-id`
- Microsoft Entra tenant ID for Microsoft Graph Defender XDR query auth

`--client-id`
- Service principal client ID for Microsoft Graph Defender XDR query auth

`--client-secret`
- Service principal client secret for Microsoft Graph Defender XDR query auth

`--query`
- Inline Defender XDR KQL query

`--query-file`
- Path to a file containing the Defender XDR KQL query

`--dump-table`
- Defender XDR advanced hunting table to dump by name

`--dump-lookback`
- KQL timespan used for the dump lookback
- Default: `30d`
- Examples: `7d`, `12h`, `90m`

`--dump-time-column`
- Table time column used for the lookback filter
- Default: `Timestamp`

`--dump-row-limit`
- Maximum rows per dump query before partitioning
- Default: `30000`

`--dump-parallelism`
- Maximum number of partition chunks queried in parallel
- Default: `4`

`--output`
- Path for the raw query JSON response
- Default: `results.json`

`--adx-export`
- Write ADX helper files next to `--output`

`--opengraph-export`
- Write a BloodHound OpenGraph payload next to `--output`

`--bloodhound-url`
- BloodHound base URL

`--bloodhound-token`
- BloodHound JWT bearer token

`--bloodhound-token-id`
- BloodHound API token ID for signed requests

`--bloodhound-token-key`
- BloodHound API token key for signed requests

`--bloodhound-upload-generated`
- After `--opengraph-export`, upload the generated OpenGraph graph file and icon file to BloodHound

`--bloodhound-upload-file`
- Upload an existing OpenGraph graph file to BloodHound

`--bloodhound-upload-icons-file`
- Upload an existing BloodHound custom node icon payload

`--adx-cluster`
- ADX engine cluster URI, for example `https://cluster.region.kusto.windows.net`

`--adx-database`
- ADX database name

`--adx-table`
- ADX table name
- Optional for `--adx-export`
- Required for `--adx-upload-file`

`--adx-mapping`
- ADX JSON ingestion mapping name
- Default: `<table>_json`

`--adx-upload-file`
- Path to the JSON file to ingest into ADX
- Supported inputs:
  - raw Defender API response JSON with `Schema` and `Results`
  - JSON array of objects
  - newline-delimited JSON

`--adx-batch-size`
- Number of rows to ingest per ADX request
- Default: `500`

`--adx-tenant-id`
- Microsoft Entra tenant ID for ADX auth
- Uses `ADX_TENANT_ID`

`--adx-client-id`
- Service principal client ID for ADX auth
- Uses `ADX_CLIENT_ID`

`--adx-client-secret`
- Service principal client secret for ADX auth
- Uses `ADX_CLIENT_SECRET`

`--adx-resource`
- OAuth resource for ADX access tokens
- Default: `https://api.kusto.windows.net`

`--endpoint`
- Microsoft Graph base URL for Defender XDR hunting
- Default: `https://graph.microsoft.com/v1.0`

`--resource`
- Microsoft Graph OAuth resource
- Default: `https://graph.microsoft.com`

`--login-base-url`
- Microsoft Entra login base URL
- Default: `https://login.microsoftonline.com`

`--env-file`
- Path to a dotenv file
- Default: `.env`

`--timeout`
- HTTP timeout for API calls
- Default: `60s`

## Useful flags

- `--endpoint`: defaults to `https://graph.microsoft.com/v1.0`
- `--resource`: defaults to `https://graph.microsoft.com`
- `--adx-cluster`: ADX cluster URI
- `--adx-database`: ADX database name
- `--env-file`: defaults to `.env`
- `--adx-export`: also write ADX ingestion files
- `--adx-table`: table name to use in the generated ADX schema
- `--adx-mapping`: ingestion mapping name to use in the generated ADX schema
- `--adx-upload-file`: upload a JSON file into ADX
- `--adx-batch-size`: defaults to `500`
- `--dump-table`: dump an entire table by name
- `--dump-lookback`: defaults to `30d`
- `--timeout`: defaults to `60s`

`--resource` defaults to Microsoft Graph because the query mode uses the Defender XDR hunting API through Graph.

## Permissions

For query mode, your app registration needs the Microsoft Graph `ThreatHunting.Read.All` application permission, and admin consent must be granted.
