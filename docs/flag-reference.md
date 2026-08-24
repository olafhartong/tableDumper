# Complete flag reference

This page lists every flag registered by the application. Follow the guide link in the last column for behavior, dependencies, and examples.

| Flag | Value | Default or environment | Purpose | Guide |
|---|---|---|---|---|
| `--auth` | `auto`, `sp`, `azcli`, `none` | `auto` | Select token acquisition mode for Graph and ADX actions. | [Authentication](authentication-and-networking.md#--auth) |
| `--tenant-id` | string | `AZURE_TENANT_ID` | Microsoft Entra tenant for Defender/Graph authentication. | [Authentication](authentication-and-networking.md#--tenant-id) |
| `--client-id` | string | `AZURE_CLIENT_ID` | Service-principal application ID for Defender/Graph. | [Authentication](authentication-and-networking.md#--client-id) |
| `--client-secret` | string | `AZURE_CLIENT_SECRET` | Service-principal secret for Defender/Graph. | [Authentication](authentication-and-networking.md#--client-secret) |
| `--query` | KQL string | empty | Run an inline Defender XDR advanced hunting query. | [Queries](queries-and-dumps.md#--query) |
| `--query-file` | path | empty | Read the Defender XDR query from a UTF-8 text file. | [Queries](queries-and-dumps.md#--query-file) |
| `--dump-table` | identifier | empty | Collect a whole advanced hunting table over a lookback window. | [Table dumps](queries-and-dumps.md#--dump-table) |
| `--dump-lookback` | KQL timespan | `30d` | Set the time window for a table dump. | [Table dumps](queries-and-dumps.md#--dump-lookback) |
| `--dump-time-column` | identifier | `Timestamp` | Select the table column used for lookback filtering. | [Table dumps](queries-and-dumps.md#--dump-time-column) |
| `--dump-row-limit` | positive integer | `30000` | Set the query and table-dump threshold that triggers hash partitioning. | [Queries and dumps](queries-and-dumps.md#--dump-row-limit) |
| `--dump-parallelism` | positive integer | `1` | Deprecated compatibility option; requests remain sequential. | [Table dumps](queries-and-dumps.md#--dump-parallelism) |
| `--output` | path | `results.json` | Set the main Defender query or dump output path. | [Output](queries-and-dumps.md#--output) |
| `--adx-export` | boolean | `false` | Generate ADX NDJSON and KQL sidecars for collected results. | [ADX export](azure-data-explorer.md#--adx-export) |
| `--opengraph-export` | boolean | `false` | Generate BloodHound OpenGraph and icon sidecars. | [OpenGraph](bloodhound-and-opengraph.md#--opengraph-export) |
| `--adx-cluster` | URI | `ADX_CLUSTER` | ADX engine cluster used for direct upload. | [ADX upload](azure-data-explorer.md#--adx-cluster) |
| `--adx-database` | string | `ADX_DATABASE` | ADX database used for direct upload. | [ADX upload](azure-data-explorer.md#--adx-database) |
| `--adx-table` | identifier | derived for export; required for upload | Set the ADX destination/schema table name. | [ADX](azure-data-explorer.md#--adx-table) |
| `--adx-mapping` | identifier | `<table>_json` | Set the JSON ingestion mapping name. | [ADX](azure-data-explorer.md#--adx-mapping) |
| `--adx-upload-file` | path | empty | Upload Defender JSON, a JSON object/array, or NDJSON to ADX. | [ADX upload](azure-data-explorer.md#--adx-upload-file) |
| `--adx-batch-size` | positive integer | `500` | Set rows per inline ADX ingestion request. | [ADX upload](azure-data-explorer.md#--adx-batch-size) |
| `--adx-auth` | `auto`, `sp`, `azcli`, `none` | inherits `--auth`; `ADX_AUTH` | Override authentication for direct ADX uploads. | [ADX authentication](azure-data-explorer.md#adx-authentication-flags) |
| `--adx-tenant-id` | string | `ADX_TENANT_ID` | Microsoft Entra tenant for ADX authentication. | [ADX authentication](azure-data-explorer.md#adx-authentication-flags) |
| `--adx-client-id` | string | `ADX_CLIENT_ID` | Service-principal application ID for ADX. | [ADX authentication](azure-data-explorer.md#adx-authentication-flags) |
| `--adx-client-secret` | string | `ADX_CLIENT_SECRET` | Service-principal secret for ADX. | [ADX authentication](azure-data-explorer.md#adx-authentication-flags) |
| `--adx-resource` | URI | `ADX_RESOURCE`, then `https://api.kusto.windows.net` | Set the ADX OAuth token audience. | [ADX authentication](azure-data-explorer.md#--adx-resource) |
| `--bloodhound-url` | URI | `BLOODHOUND_URL` | BloodHound base URL for uploads and custom-node operations. | [BloodHound upload](bloodhound-and-opengraph.md#--bloodhound-url) |
| `--bloodhound-token` | secret string | `BLOODHOUND_TOKEN` | Use JWT bearer authentication for BloodHound. | [BloodHound auth](bloodhound-and-opengraph.md#bloodhound-authentication-flags) |
| `--bloodhound-token-id` | string | `BLOODHOUND_TOKEN_ID` | API token ID for signed BloodHound requests. | [BloodHound auth](bloodhound-and-opengraph.md#bloodhound-authentication-flags) |
| `--bloodhound-token-key` | secret string | `BLOODHOUND_TOKEN_KEY` | Base64 API token key for signed BloodHound requests. | [BloodHound auth](bloodhound-and-opengraph.md#bloodhound-authentication-flags) |
| `--bloodhound-upload-generated` | boolean | `false` | Upload graph and icon sidecars generated by the current query. | [Generated upload](bloodhound-and-opengraph.md#--bloodhound-upload-generated) |
| `--bloodhound-upload-file` | path | empty | Upload an existing OpenGraph JSON or ZIP file. | [Existing graph upload](bloodhound-and-opengraph.md#--bloodhound-upload-file) |
| `--bloodhound-upload-icons-file` | path | empty | Create or update custom node types from an icon sidecar. | [Icon upload](bloodhound-and-opengraph.md#--bloodhound-upload-icons-file) |
| `--pseudonymize` | boolean | `false` | Pseudonymize selected fields before collected data is written. | [Pseudonymization](pseudonymization.md#--pseudonymize) |
| `--pseudonymize-filenames` | boolean | `false` | Pseudonymize filenames and keep matching path/command-line references linked. | [Filename linking](pseudonymization.md#--pseudonymize-filenames) |
| `--pseudonym-map` | path | secure temporary file | Set a reusable, sensitive pseudonym mapping vault. | [Mapping vault](pseudonymization.md#--pseudonym-map) |
| `--pseudonym-fields` | comma-separated patterns | `PSEUDONYM_FIELDS`, then built-in table policy | Override the selected-column allowlist. | [Field policy](pseudonymization.md#--pseudonym-fields) |
| `--pseudonym-replacements-file` | path | `PSEUDONYM_REPLACEMENTS_FILE` | Load configured literal replacements from JSON. | [Replacements](pseudonymization.md#--pseudonym-replacements-file) |
| `--pseudonym-map-retention` | `keep`, `delete` | `keep` | Choose what happens to the mapping vault after collection. This is non-interactive. | [Retention](pseudonymization.md#--pseudonym-map-retention) |
| `--endpoint` | URI | `https://graph.microsoft.com/v1.0` | Override the Microsoft Graph API base URL. | [Networking](authentication-and-networking.md#--endpoint) |
| `--resource` | URI | `https://graph.microsoft.com` | Override the Defender/Graph OAuth audience. | [Networking](authentication-and-networking.md#--resource) |
| `--login-base-url` | URI | `https://login.microsoftonline.com` | Override the Microsoft Entra OAuth base URL. | [Networking](authentication-and-networking.md#--login-base-url) |
| `--insecure-skip-verify` | boolean | `false` | Disable HTTPS certificate validation for in-process HTTP calls. | [TLS](authentication-and-networking.md#--insecure-skip-verify) |
| `--env-file` | path | `.env` | Select the dotenv file used to populate supported defaults. | [Dotenv](authentication-and-networking.md#--env-file) |
| `--timeout` | Go duration | `60s` | Set the shared HTTP-client timeout. | [Networking](authentication-and-networking.md#--timeout) |

## Automatic help flags

Go's flag parser also recognizes `-h` and `-help`; the conventional `--help` spelling works as well. These print usage and the registered defaults. They are automatic help aliases rather than application configuration fields.
