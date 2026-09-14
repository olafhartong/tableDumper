# Queries and table dumps

These flags control the query source, query input, whole-table collection, partitioning, and the main JSON output.

## `--source`

Selects the service that queries and table dumps run against. Default: `defender`.

| Value | Service |
|---|---|
| `defender` | Microsoft Defender XDR advanced hunting through Microsoft Graph (`POST /security/runHuntingQuery`). |
| `loganalytics` | A Log Analytics workspace, including Microsoft Sentinel tables such as `SigninLogs`, `AuditLogs`, `OfficeActivity`, and `SecurityEvent`, through the Log Analytics query API (`POST /workspaces/{workspace-id}/query`). |

```bash
./tableDumper \
  --auth azcli \
  --source loganalytics \
  --workspace-id 00000000-0000-0000-0000-000000000000 \
  --dump-table SigninLogs \
  --dump-lookback 7d \
  --output signinlogs.json
```

Both sources share the same pipeline: counting, hash partitioning, pseudonymization, ADX export and upload, OpenGraph export, and the `Schema`/`Results` output envelope. Log Analytics returns rows as arrays; they are converted to objects keyed by column name. Column types keep their lowercase Kusto names (`string`, `datetime`, `long`, `dynamic`, and so on), which the partition key and ADX schema treat the same as Defender's type names. `dynamic` values arrive as JSON text; objects and arrays are decoded so they are written and ingested as nested values. Dynamic scalars arrive as their raw text (`dynamic("text")` as `text`, `dynamic(5)` as `5`) and are kept as strings.

`--source loganalytics` requires `--workspace-id` (see [Log Analytics authentication and networking](authentication-and-networking.md#--workspace-id)). Differences from the Defender source:

- `--dump-time-column` defaults to `TimeGenerated`.
- A table dump filtering on `TimeGenerated` also sends the fixed dump window, padded by one second, as the request `timespan`. The query's own filter remains authoritative. With another `--dump-time-column`, no `timespan` is sent, because the service applies it to `TimeGenerated` and could exclude rows the query selects. Free-form queries never send a `timespan`; the query text alone defines the time range.
- Table dumps exclude rows ingested after the cutoff, as for Defender (see [`--dump-lookback`](#--dump-lookback)). Some Log Analytics tables, such as Entra ID audit logs, can receive events many hours after their `TimeGenerated`, so choose an older window when recent data must be complete.
- Requests ask the service for up to ten minutes (`Prefer: wait=600`). The shared `--timeout` still applies, so raise it for long-running queries.
- The service can answer HTTP 200 with a partial result and an `error` object when a limit is reached. Such a response is never used. A result-size error triggers the same automatic hash-partition retry as Defender's result-size error, for queries and table dumps; any other partial result fails the collection.
- HTTP 429 responses are retried with the same waiting behavior as Defender.

The query API returns at most 500,000 records and 64 MB per response. Keep `--dump-row-limit` well below the record limit, and lower it for wide tables so each chunk stays under the size limit. A chunk that still exceeds the size limit is retried with more hash partitions; a single row that exceeds it fails the collection.

Tables with restricted table-level access can return no rows rather than an error, so an empty result is not proof that the table is empty. Check the workspace permissions described in [Log Analytics authentication](authentication-and-networking.md#--workspace-id).

## `--query`

Runs the supplied string as a KQL query against the selected `--source`. The tool first appends a count operation to the complete query pipeline. Small results then run normally; large results are hash-partitioned and streamed sequentially into one output file.

```bash
./tableDumper \
  --auth azcli \
  --query 'DeviceInfo | take 100' \
  --output devices.json
```

`--query` cannot be combined with `--query-file` or `--dump-table`. Shell quoting matters: single quotes are generally safest for KQL that contains `$`, quotes, or other shell-sensitive characters.

The result is written as the Graph hunting response envelope, containing `Schema` and `Results`. `--adx-export` and `--pseudonymize` work with both normal and partitioned results. `--opengraph-export` requires a non-partitioned result because graph construction loads all rows in memory.

## `--query-file`

Reads KQL from a file and trims surrounding whitespace. It uses the same count and automatic partitioning pipeline as `--query`.

```bash
./tableDumper --auth azcli --query-file queries/alerts.kql --output alerts.json
```

The file must exist and contain a non-empty query. `--query-file` cannot be combined with `--query` or `--dump-table`. This form is preferable for long, version-controlled queries because it avoids shell-quoting problems.

## `--dump-table`

Dumps a Defender XDR advanced hunting or Log Analytics table over a bounded time window.

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceProcessEvents \
  --dump-lookback 14d \
  --output device-process-events.json
```

The table name must be a safe KQL identifier: letters or underscore first, followed by letters, digits, or underscores. The tool constructs the KQL itself and first counts matching rows. `--dump-table` is mutually exclusive with both query-input flags.

Small dumps run as one query. Large dumps resolve the result schema once with `take 0`, then partition an ordered tuple of known scalar columns. Dynamic objects and unknown column types are excluded from the key. The same tuple and SHA-256 calculation are reused for each count, retry, and sequential download. Partitioned output is streamed through an atomic temporary file so the complete result set does not need to remain in memory.

### Partition safety and limitations

Scalar columns are sorted by exact column name, converted to strings, and encoded as a `pack_array` tuple. Null scalar values consistently become empty strings; equal keys share a bucket. A fixed SHA-256 prefix determines the bucket, without depending on unordered property-bag serialization or the version-dependent `hash()` algorithm. No partition field is added to exported rows.

Partition counts must be unique, in range, and add up to the initial count. Every downloaded chunk must have exactly its advertised row count and retain the key columns' types. A mismatch aborts temporary outputs and keeps previously published files. These checks detect incomplete responses and many source changes; matching counts alone do not prove snapshot consistency.

A result containing only dynamic/unknown columns fails safely when partitioning is needed. Project a stable scalar event identifier from the dynamic data in the original query. If too many rows have identical scalar keys, increasing the partition count cannot separate them; attempts are bounded and the collection returns an error. Small results can still be downloaded without a partition key.

Free-form query mode reuses the supplied pipeline without rewriting its expressions. Use explicit absolute time bounds and immutable source values when completeness matters. Avoid `rand()`, unordered `take`, changing aggregations, and strings derived from unordered dynamic bags in a partitioned query. Late-arriving records or updates can change membership even within a fixed time window; this API does not provide a cross-request snapshot. Table dumps add an ingestion-time cutoff for that reason; add `| where ingestion_time() < datetime(...)` to a free-form query to get the same effect.

The partition contract follows Microsoft's documentation for [unordered `pack_all()` objects](https://learn.microsoft.com/en-us/kusto/query/pack-all-function?view=microsoft-fabric), [ordered arrays](https://learn.microsoft.com/en-us/kusto/query/pack-array-function?view=microsoft-fabric), and [stable SHA-256 hashing](https://learn.microsoft.com/en-us/kusto/query/hash-sha256-function?view=microsoft-fabric).

## `--dump-lookback`

Sets the time range used by `--dump-table`. Default: `30d`.

Accepted values are simple KQL timespan literals such as:

- `7d`
- `12h`
- `90m`
- `1.5h`
- `30s`

The collection captures one UTC cutoff before counting. Every table request uses the same half-open window: `Timestamp >= (datetime(cutoff) - lookback) and Timestamp < datetime(cutoff)` (with the configured time column). Every request also excludes rows ingested at or after the cutoff with `isnull(ingestion_time()) or ingestion_time() < datetime(cutoff)`, so events that arrive during the collection cannot change counts between requests. Events can be ingested hours after their event time, so a window that ends near the present misses events that have not arrived yet; use an older window when the most recent hours must be complete. Complex KQL expressions are rejected; use `--query` or `--query-file` when the selection needs a more involved time condition.

This flag has no effect unless `--dump-table` is set.

## `--dump-time-column`

Selects the column used for the dump's lookback filter. Default: `Timestamp`, or `TimeGenerated` with `--source loganalytics`. An explicitly supplied value is always used as given.

```bash
./tableDumper \
  --dump-table SomeTable \
  --dump-time-column EventTime \
  --dump-lookback 6h
```

The value must be a safe KQL identifier. Choose a column that exists in the selected table and has a datetime-compatible type. This flag has no effect in free-form query mode.

## `--dump-row-limit`

Controls the maximum target size of each query or table-dump request. Default: `30000`; the value must be greater than zero.

- If the initial row count is below the limit, the query is requested normally.
- If the count is equal to or above the limit, the tool counts hash partitions.
- If any partition is still at or above the limit, the partition count is doubled and checked again.
- Non-empty partitions are then downloaded sequentially and streamed into the output.
- If the source reports that even a below-threshold query, table dump, or partition exceeds its byte-size limit, the tool retries with more hash partitions automatically. A single row above that limit fails the collection.

This is a query-size and memory-control setting, not a cap on the total number of rows written. Lower values create more requests; higher values create larger responses.

## `--dump-parallelism`

Deprecated compatibility flag. Default: `1`.

The value is still parsed and must be greater than zero, but it no longer changes execution: partition requests are always sequential. Existing scripts may continue supplying the flag, but new scripts should omit it.

## `--output`

Sets the main JSON output path. Default: `results.json`. It must not be empty.

For a query or table dump, the main file contains the Defender response shape:

```json
{
  "Schema": [],
  "Results": []
}
```

The parent directory is created when necessary. Normal query and small-dump results are written directly with owner-only file permissions. Partitioned queries and dumps stream through a temporary file and rename it after every chunk has completed.

The output basename also determines optional sidecar names:

| Option | Sidecars for `results.json` |
|---|---|
| `--adx-export` | `results.adx.json`, `results.adx.kql` |
| `--opengraph-export` | `results.opengraph.json`, usually `results.opengraph.icons.json` |

A pseudonym mapping file, replacements file, or `--manifest` may not use the same path as the main output or these enabled sidecars.

## `--manifest`

Creates or updates a JSON collection manifest describing what the run captured. Each `--dump-table`, `--query`, or `--query-file` run records one table entry, so a set of runs sharing one manifest describes a whole collection. Default: disabled.

```bash
./tableDumper --dump-table DeviceProcessEvents --dump-lookback 7d \
  --output incident/device-process-events.json --manifest incident/manifest.json

./tableDumper --source loganalytics --workspace-id <workspace-id> \
  --query-file queries/incident-signins.kql \
  --output incident/signins.json \
  --manifest incident/manifest.json --manifest-table IncidentSignins
```

Every table has one of four statuses. They are never collapsed, because a reader treats an empty result as evidence that nothing happened:

| Status | Meaning |
|---|---|
| `captured` | Collected with at least one row. `row_count`, `partitions`, `columns`, `file`, `sha256`, and `bytes` are recorded. |
| `captured_empty` | Collected successfully with zero rows. `columns` are still recorded, so an identical empty table can be created, together with the written file and its hash. |
| `not_captured` | The run did not collect the table, for example because a query, pseudonymization, or write failed. `note` explains why. |
| `absent_in_source` | The source reported that the table does not exist (a Kusto "failed to resolve table" semantic error naming that table). |

`captured_empty` means the source answered with no rows for the window, not that no such activity exists. Log Analytics defines its standard tables (such as `SecurityEvent` or `DeviceProcessEvents`) in every workspace, so an empty standard table can also mean that no connector ever sent that data, and tables with restricted table-level access can return no rows instead of an error.

Failed and absent tables still update the manifest before the run returns its error, and the run exits with an error exactly as it would without `--manifest`.

Example:

```json
{
  "schema_version": 1,
  "tool": {"name": "tableDumper", "version": "v0.0.0-20260913095812-57c7290a1b2c"},
  "created_at": "2026-09-13T09:58:12.41Z",
  "updated_at": "2026-09-13T10:02:47.03Z",
  "pseudonymization": {"enabled": true, "mode": "irreversible", "key_id": "3f9c0a7d51e2b846"},
  "tables": [
    {
      "source": "defender",
      "name": "DeviceProcessEvents",
      "status": "captured",
      "time_column": "Timestamp",
      "window": {"start": "2026-09-06T09:58:12.41Z", "end": "2026-09-13T09:58:12.41Z", "ingested_before": "2026-09-13T09:58:12.41Z"},
      "columns": [{"name": "Timestamp", "type": "datetime"}, {"name": "DeviceName", "type": "string"}],
      "row_count": 48213,
      "partitions": 4,
      "file": "device-process-events.json",
      "sha256": "9b1f…",
      "bytes": 81234567,
      "adx_data_file": "device-process-events.adx.json",
      "adx_data_sha256": "c07e…"
    },
    {
      "source": "loganalytics",
      "name": "AADRiskyUsers",
      "status": "absent_in_source",
      "time_column": "TimeGenerated",
      "window": {"start": "2026-09-06T10:02:40.12Z", "end": "2026-09-13T10:02:40.12Z", "ingested_before": "2026-09-13T10:02:40.12Z"},
      "note": "the table does not exist in the source"
    }
  ]
}
```

Rules:

- Entries are keyed by `source` and `name`. Re-running a table replaces its entry, including replacing a previous `captured` entry with `not_captured` when the new run fails. Tables are sorted by that key.
- Column types use the Kusto names produced by the ADX export mapping (`string`, `datetime`, `long`, `int`, `real`, `bool`, `guid`, `decimal`, `dynamic`).
- `file` and `adx_data_file` are relative to the manifest's directory, with forward slashes. Hashes are SHA-256 over the final published files.
- Table dumps record `time_column` and the fixed half-open `window` used by the query. `window.ingested_before` is the ingestion-time cutoff: rows ingested at or after it were excluded, so events that arrived later for the same window are not in the collection. Query entries have no window.
- The manifest is validated when it is loaded and before it is written, and saved atomically with owner-only `0600` permissions. An existing invalid manifest stops the run before any query is sent.
- A tool `version` is the module version from the build. Local builds from a Git checkout report a pseudo-version with the commit time and revision, such as `v0.0.0-20260913095812-57c7290a1b2c`, with `+dirty` for modified trees. Builds without module or VCS information record the revision if known, otherwise `(devel)` or `unknown`.
- Runs are not locked against each other. Do not run collections that share a manifest concurrently.

With `--pseudonymize`, the manifest contains no original values: no query text, no tenant or workspace ID, and failure notes record only the failure category because service errors can echo query text. It records the vault's mode and `key_id` (never the seed), so the manifest can be matched to its vault. Every run that joins a manifest must use the same pseudonymization setup; a run with pseudonymization disabled, a different vault, or a different vault mode is rejected before it collects anything. Without `--pseudonymize`, query entries record the query text and failure notes include the error. File paths are recorded as given, so do not put identifiers in output file names.

An empty result cannot always prove a table is empty in the source: Log Analytics tables protected by table-level access can return no rows without an error.

The manifest path must differ from `--output`, every enabled ADX/OpenGraph sidecar, `--pseudonym-map`, `--pseudonym-replacements-file`, and `--query-file`.

## `--manifest-table`

Sets the table name recorded in `--manifest` for a `--query` or `--query-file` result. It is required when `--manifest` is used with query input, and rejected with `--dump-table`, which records its own table name. The value must be a safe identifier: letters or underscore first, followed by letters, digits, or underscores.

A query result is recorded as `absent_in_source` only when the source reports that a table with exactly this name does not exist. A missing table under a different name in the query is recorded as `not_captured`.

## Common combinations

Query and pseudonymize:

```bash
./tableDumper \
  --auth azcli \
  --query-file queries/logons.kql \
  --output logons.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --pseudonym-map-retention keep
```

Stream a large table and generate ADX artifacts:

```bash
./tableDumper \
  --auth sp \
  --dump-table DeviceEvents \
  --dump-lookback 30d \
  --dump-row-limit 25000 \
  --output device-events.json \
  --adx-export \
  --adx-table DeviceEventsArchive
```

OpenGraph export works for non-partitioned query results and non-partitioned table dumps. A result that crosses the partition threshold rejects `--opengraph-export` because graph construction requires all rows in memory.
