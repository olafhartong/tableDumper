# Queries and table dumps

These flags control Defender XDR advanced hunting input, whole-table collection, partitioning, and the main JSON output.

## `--query`

Runs the supplied string as a Defender XDR advanced hunting KQL query. The tool first appends a count operation to the complete query pipeline. Small results then run normally; large results are hash-partitioned and streamed sequentially into one output file.

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

Dumps a Defender XDR advanced hunting table over a bounded time window.

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceProcessEvents \
  --dump-lookback 14d \
  --output device-process-events.json
```

The table name must be a safe KQL identifier: letters or underscore first, followed by letters, digits, or underscores. The tool constructs the KQL itself and first counts matching rows. `--dump-table` is mutually exclusive with both query-input flags.

Small dumps run as one query. Large dumps are divided into deterministic hash partitions based on the complete row, and those partition requests are processed sequentially. Partitioned output is streamed through an atomic temporary file so the complete result set does not need to remain in memory.

## `--dump-lookback`

Sets the time range used by `--dump-table`. Default: `30d`.

Accepted values are simple KQL timespan literals such as:

- `7d`
- `12h`
- `90m`
- `1.5h`
- `30s`

The value is inserted into a `ago(...)` filter. Complex KQL expressions are rejected; use `--query` or `--query-file` when the selection needs a more involved time condition.

This flag has no effect unless `--dump-table` is set.

## `--dump-time-column`

Selects the column used for the dump's lookback filter. Default: `Timestamp`.

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
- If Defender reports that even a below-threshold result or partition exceeds its byte-size limit, the tool retries with more hash partitions automatically.

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

A pseudonym mapping or replacements file may not use the same path as the main output or these enabled sidecars.

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
