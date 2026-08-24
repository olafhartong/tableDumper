# Defender for Endpoint KQL Dumper

Small Go CLI to:

- run a Microsoft Defender XDR advanced hunting query through Microsoft Graph, automatically partitioning large result sets, and write the JSON response to disk
- dump a whole Defender XDR advanced hunting table over a lookback window, partitioning large dumps into chunks automatically
- generate Azure Data Explorer ingestion artifacts from those results
- generate a BloodHound OpenGraph JSON payload from graph-shaped Defender results
- upload a JSON file into an Azure Data Explorer table in configurable batches
- pseudonymize collected identifiers with an embedded NER model before any result is written

## What it does

- Runs `POST /security/runHuntingQuery` against the Microsoft Graph security API for Defender XDR advanced hunting
- Authenticates with either:
  - a Microsoft Entra service principal
  - Azure CLI credentials from `az login`
- Writes the API response to a pretty-printed JSON file
- Can dump an entire table by name with a default `30d` lookback
- Counts query and table-dump results first, then uses hash-partitioned chunk queries when a result set reaches `30000` rows or Defender rejects an unpartitioned query for exceeding its result-size limit
- Optionally writes Azure Data Explorer ingestion artifacts
- Optionally writes a BloodHound OpenGraph JSON payload
- Optionally uploads JSON data into Azure Data Explorer
- Optionally replaces people, organizations, accounts, hosts, domains, network addresses, and identifiers with consistent realistic pseudonyms

## Build

```bash
go build -o tableDumper .
```

## Documentation

Detailed documentation for every command-line flag is available in [docs/README.md](docs/README.md), including focused guides for collection, authentication, pseudonymization, Azure Data Explorer, and BloodHound/OpenGraph workflows.

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

### 6. Pseudonymize a collection

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceLogonEvents \
  --output device-logons.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json
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

Query mode first counts the rows produced by the complete KQL pipeline. Results below `--dump-row-limit` are requested normally. Larger results are divided into deterministic hash partitions, requested sequentially, and streamed into the same `Schema`/`Results` JSON envelope used for small queries. If a result is below the row threshold but still exceeds Defender's byte-size limit, the tool automatically retries it with progressively smaller hash partitions.

## Table dump

Use `--dump-table` to dump all rows from a Defender XDR advanced hunting table over a lookback window. The tool first runs a count query:

```kql
<table>
| where Timestamp >= ago(<lookback>)
| count
```

If the count is below `30000`, it dumps the table directly. If the count is `30000` or higher, it counts hash partitions and then queries each non-empty partition sequentially, streaming each completed chunk to one JSON response file with the usual `Schema` and `Results` fields. Sequential requests avoid exhausting the tenant's Defender hunting CPU quota. If Defender responds with HTTP 429, the tool pauses for the server-specified interval and retries instead of aborting the dump. Partitioned dumps do not keep the full result set in memory; only the current chunk response is held while it is written.

When `--adx-export` is used with a partitioned dump, the ADX newline-delimited JSON sidecar is streamed at the same time as the main output file.

`--opengraph-export` is only supported for non-partitioned queries and table dumps because building the OpenGraph payload requires all rows in memory.

During a table dump, progress is written to stderr. It reports the matching row count, partition sizing, and each completed partition chunk. The final summary report is still written to stdout.

Example:

```bash
./tableDumper \
  --auth sp \
  --dump-table DeviceProcessEvents \
  --dump-lookback 14d \
  --output device-process-events.json
```

By default, the lookback filter uses the `Timestamp` column. Use `--dump-time-column` only for tables with a different time column.

## NER-based pseudonymization

Use `--pseudonymize` to transform downloaded rows before the main JSON response or any ADX/OpenGraph sidecar is written. The implementation follows the context-preserving approach from [zolderio/token-proxy](https://github.com/zolderio/token-proxy), adapted for local Defender data collection rather than LLM traffic.

Pseudonymization is field-scoped. A value is inspected only when its column matches the active field allowlist; every other column, including nested content, is copied unchanged. For table dumps, the program selects a built-in policy keyed by `--dump-table`. Process/file/network event tables include their applicable account, email/UPN, filename, domain, device, folder-path, and Azure resource columns; narrower tables such as `DeviceInfo` and `EmailEvents` receive smaller policies. The built-ins also cover schema variants such as `UserPrincipal`, `HomeDirectory`, `FilePath`, `*Fqdn`, `Computer`, `ResourceGroup`, and the typed `_s`/`_g` suffixes used by custom Log Analytics columns. Ambiguous names such as `Name`, `User`, `Host`, `UserId`, and `Resource` are enabled only for tables where their schema description gives them one of those meanings. Arbitrary query mode and unknown tables use a conservative semantic fallback. All built-in policies deliberately exclude generic messages, general command-line content, named pipes, timestamps, versions, IP-address fields, SIDs, scope/type metadata, and unrelated identifiers. Credential masking within command-line fields is always applied as a safety exception.

Semantically related fields are linked before replacement. Account families such as `AccountName`/`AccountUpn`/`AccountDomain` and `InitiatingProcessAccount*` reuse one generated identity even when their source strings differ. Missing selected identity components are synthesized from that account profile rather than mapping an empty string globally. A device FQDN in the event uses the primary account domain as its suffix. Existing inconsistent aliases from an older mapping vault are reconciled and saved as one coherent identity. Sender address/domain pairs and device hostname/FQDN/domain families behave similarly, and the aliases are retained in the mapping vault for consistency across rows and runs.

Filenames are unchanged by default. Add `--pseudonymize-filenames` to replace them. When enabled, each process family stays internally consistent: `FileName`, the filename at the end of `FolderPath`, and executable references in `ProcessCommandLine` share one replacement; the corresponding initiating-process and parent-process families use their own replacements. Command-line matches may include or omit `.exe`, while partial names are left untouched.

Sensitive values in `ProcessCommandLine`, `InitiatingProcessCommandLine`, and other command-line fields are always masked with `***` whenever `--pseudonymize` is enabled. This includes named username/password arguments, API keys and tokens, app/client IDs and secrets, tenant IDs, common cloud credential environment variables, connection strings, authorization headers, URL credentials, UPNs, and account identities known from the same event. Quoting and unrelated command-line arguments are preserved.

For a strict table-specific selection, provide exact column names:

```bash
./tableDumper --dump-table DeviceProcessEvents --output processes.json \
  --pseudonymize \
  --pseudonym-fields 'AccountName,InitiatingProcessAccountName,FileName,InitiatingProcessFileName,DeviceName,FolderPath,InitiatingProcessFolderPath'
```

`--pseudonym-fields` overrides the built-in table policy. The override is case-insensitive and accepts `*` and `?` wildcards. Quote wildcard values in the shell. For example, `'*AccountName,*FileName,*FolderPath'` selects those column families. `PSEUDONYM_FIELDS` provides the same override through the environment. Using `'*'` restores broad content scanning, but increases false positives and is not recommended for routine collections.

The pipeline combines:

- an English NER model embedded in the Go binary for people and organizations
- field-aware recognition for Defender account, device, tenant, domain, and object identifiers
- regex recognition for emails, domains, IP addresses, SIDs, GUIDs, MAC addresses, phone numbers, and usernames in paths or `DOMAIN\\user` values
- optional configured literal replacements for specific words and phrases
- recursive handling of nested objects, arrays, and JSON stored inside string fields

Pseudonyms look realistic and preserve useful structure. The same person, account, host, or identifier receives the same replacement everywhere while the same mapping file is in use. Host roles such as domain controller/server/workstation, private versus public IP context, and identifier formats are retained where possible.

Without `--pseudonymize-filenames`, filenames remain original in all locations, including `C:\Windows`, `Program Files`, path basenames, and process command lines.

Azure Resource IDs preserve their hierarchy. Subscription IDs, resource groups, and resource-name components are pseudonymized consistently, while structural segments such as `subscriptions`, `resourceGroups`, provider namespaces, and resource types remain intact. Standalone `SubscriptionId`, `ResourceGroup`, and `ResourceGroupName` fields use the same component mappings as the full resource paths.

For values that need a specific replacement, create a JSON file such as:

```json
{
  "case_sensitive": false,
  "whole_words": true,
  "replacements": [
    {
      "find": ["Contoso", "Contoso Ltd", "Contoso Corporation"],
      "replace": "Northbridge Group"
    },
    {"find": "Project Falcon", "replace": "Project Aurora"},
    {"find": "ACME+Ops", "replace": "Juniper Services"}
  ]
}
```

`find` accepts either one string or a list of strings. A list is useful for aliases that should all receive the same configured replacement. See [`examples/pseudonym-replacements.json`](examples/pseudonym-replacements.json) for a complete example.

Then pass it with the collection:

```bash
./tableDumper --dump-table DeviceInfo --output devices.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --pseudonym-replacements-file ./replacements.json
```

These are literal replacements, not regular expressions, so characters such as `.`, `+`, `(`, and `\\` have no special meaning. Matching is case-insensitive and restricted to whole words by default. Set `case_sensitive` to `true` or `whole_words` to `false` to change those behaviors. Longer configured phrases win when rules overlap, and configured matches take precedence over NER and identifier recognition. Unmatched identifiers in the same value are still pseudonymized normally. Every alias is tracked separately in the mapping vault, even when several aliases share one replacement.

Configured matches in selected fields are also recorded in the mapping vault, which detects attempts to reuse the vault with a different replacement. Protect the replacement configuration itself if its `find` values are sensitive. The path can also be supplied through `PSEUDONYM_REPLACEMENTS_FILE`.

The mapping file is a sensitive, reversible vault: it contains both original values and their pseudonyms. It is written atomically with `0600` permissions. When `--pseudonym-map` is omitted, the tool creates a secure temporary mapping file and prints its path. To use consistent replacements across several table collections, keep the file and pass its path to each run:

```bash
./tableDumper --dump-table DeviceInfo --output devices.json \
  --pseudonymize --pseudonym-map ./collection.pseudonyms.json

./tableDumper --dump-table DeviceLogonEvents --output logons.json \
  --pseudonymize --pseudonym-map ./collection.pseudonyms.json
```

After a successful collection, the mapping file is kept by default without prompting. To remove it automatically after a successful run, choose `delete` explicitly:

```bash
--pseudonym-map-retention delete
```

This is pseudonymization, not guaranteed anonymization. NER and pattern recognition can have false negatives, especially for non-English, obfuscated, image, or uncommon identifiers. Review representative output before using it for regulated or high-risk data.

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
- Authentication mode: `auto`, `sp`, `azcli`, or `none`
- Default: `auto`

`--adx-auth`
- Optional ADX-specific authentication override: `auto`, `sp`, `azcli`, or `none`
- Defaults to the value of `--auth`

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
- Maximum rows per query or table-dump chunk before partitioning
- Default: `30000`

`--dump-parallelism`
- Deprecated compatibility flag; partition requests are always sequential regardless of its value
- Default: `1`

`--output`
- Path for the query JSON response
- Default: `results.json`

`--pseudonymize`
- Apply embedded NER and identifier pseudonymization before collected data is written

`--pseudonymize-filenames`
- Also replace filenames and keep matching path and process command-line references consistent
- Requires `--pseudonymize`; default: disabled

`--pseudonym-map`
- Reusable sensitive mapping-vault path
- When omitted, a secure temporary file is created

`--pseudonym-fields`
- Override the built-in per-table field policy with a comma-separated allowlist
- Case-insensitive, with `*` and `?` wildcard support
- Can also be set with `PSEUDONYM_FIELDS`

`--pseudonym-replacements-file`
- JSON file containing literal word and phrase replacements
- Can also be set with `PSEUDONYM_REPLACEMENTS_FILE`

`--pseudonym-map-retention`
- Non-interactive mapping-file action after collection: `keep` or `delete`
- Default: `keep`

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
