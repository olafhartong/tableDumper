# tableDumper documentation

This directory is the detailed command-line reference for `tableDumper`. The root [README](../README.md) remains the quickest introduction; these pages explain every flag, its defaults, dependencies, side effects, and common combinations.

## Guides

- [Complete flag reference](flag-reference.md) — one table covering every command-line flag
- [Queries and table dumps](queries-and-dumps.md) — query input, whole-table collection, partitioning, and output
- [Authentication and networking](authentication-and-networking.md) — Microsoft Graph, Azure CLI, service principals, dotenv, endpoints, TLS, and timeouts
- [Pseudonymization](pseudonymization.md) — field policies, mapping vaults, configured replacements, and retention
- [Azure Data Explorer](azure-data-explorer.md) — ADX artifact export and direct upload
- [BloodHound and OpenGraph](bloodhound-and-opengraph.md) — OpenGraph generation, authentication, graph upload, and custom icons

## Action modes

At least one action must be requested:

1. Run one Defender XDR query with `--query` or `--query-file`.
2. Dump one Defender XDR table with `--dump-table`.
3. Upload an existing file to ADX with `--adx-upload-file`.
4. Upload an existing graph or icon file with `--bloodhound-upload-file` or `--bloodhound-upload-icons-file`.

Query input and `--dump-table` are mutually exclusive. Upload actions may run in the same invocation as a query, although separate invocations are usually easier to operate and retry.

Run `./tableDumper --help` to print the built-in summary. Both one-dash and two-dash forms are accepted by Go's flag parser, but these docs consistently use the conventional `--flag` form.

## Configuration precedence

For flags that support environment variables, precedence is:

1. An explicit command-line flag
2. The process environment
3. The selected dotenv file
4. The compiled default

Not every flag has an environment-variable equivalent. The complete mapping is in the [flag reference](flag-reference.md).
