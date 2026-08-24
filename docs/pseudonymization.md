# Pseudonymization

Pseudonymization transforms selected fields after data is downloaded and before the main JSON response or enabled ADX/OpenGraph sidecars are written. It is intended to preserve useful relationships while reducing exposure of real identifiers.

It is not a guarantee of anonymization. NER and pattern matching can miss uncommon, obfuscated, non-English, or unexpected identifiers. Review representative output before releasing sensitive or regulated data.

## `--pseudonymize`

Enables the pseudonymization pipeline for `--query`, `--query-file`, or `--dump-table`.

```bash
./tableDumper \
  --auth azcli \
  --dump-table DeviceLogonEvents \
  --output logons.json \
  --pseudonymize
```

The pipeline combines:

- built-in table-aware field allowlists
- field semantics for accounts, emails/UPNs, domains, hosts, filenames, paths, and Azure resources
- embedded English NER for applicable person and organization values
- stable, realistic pseudonym generation
- structural handling for Azure Resource IDs and file paths
- linked identity, email sender, and device field families
- optional configured literal replacements

Fields outside the active allowlist are copied unchanged. The built-in policies avoid generic text, named pipes, timestamps, versions, general command-line content, hashes, scope/type metadata, and unrelated IDs. Sensitive command-line values are the exception: credential masking described below is always applied when pseudonymization is enabled. Unknown tables and free-form queries use a conservative semantic fallback.

Filenames are also unchanged by default, even when filename and path columns are selected by the table policy. Use `--pseudonymize-filenames` when those values need to be transformed.

Pseudonymization is not applied to an existing file passed through `--adx-upload-file`, `--bloodhound-upload-file`, or `--bloodhound-upload-icons-file`.

## `--pseudonymize-filenames`

Enables filename transformation as an explicit extension of `--pseudonymize`. Default: disabled.

```bash
./tabledumper \
  --dump-table DeviceProcessEvents \
  --pseudonymize \
  --pseudonymize-filenames \
  --pseudonym-map ./collection.pseudonyms.json \
  --output processes.json
```

The related fields in each process family are transformed as one set. For example, `FileName`, the final filename in `FolderPath`, and executable references in `ProcessCommandLine` receive the same replacement. `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, and `InitiatingProcessCommandLine` form a separate set, as do matching parent-process variants.

Command-line replacement is limited to executable tokens linked to the corresponding filename field. Both `tool.exe` and an extensionless `tool` reference are recognized; partial names such as `mytool.exe` or `tool.exe.config` are left alone. Quoting, arguments, and the rest of the command line are preserved.

The option requires `--pseudonymize`. Without it, filename fields, path basenames, and executable command-line references remain original. Path processing can still replace an identity below `/Users/`, `/home/`, or `C:\Users\`.

## Command-line credential masking

When `--pseudonymize` is enabled, sensitive values in `ProcessCommandLine`, `InitiatingProcessCommandLine`, and other `*CommandLine` fields are always replaced with `***`. This protection does not require `--pseudonymize-filenames` and does not store secret values in the pseudonym mapping vault.

The masker covers:

- username, user ID, login, password, credential, and short `-u`/`-p` arguments
- API/access/secret keys, subscription keys, tokens, SAS signatures, and authorization headers
- app/application/client IDs and secrets, plus tenant IDs
- common Azure, ARM, AWS, and GitHub credential environment variables
- connection-string credentials and escaped JSON credential properties
- URL user information, email/UPN values, recognizable JWTs, and AWS access-key IDs
- account values known from the same event and usernames inside common user-home paths

Separated, `=`, `:`, quoted, and common connection-string forms retain their original syntax while only the value becomes `***`. Arbitrary unlabeled secret strings cannot be distinguished reliably from ordinary arguments, so secrets should still be supplied through clearly named options or environment variables whenever possible.

## `--pseudonym-map`

Sets the path of the reusable mapping vault. The vault contains the random seed plus original-to-pseudonym mappings, which keeps replacements consistent across rows, tables, and separate collection runs.

```bash
./tableDumper \
  --dump-table DeviceInfo \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --pseudonym-map-retention keep
```

When omitted, the tool creates a secure temporary mapping file and reports its path on stderr. The file is saved atomically with owner-only `0600` permissions.

The vault is sensitive and effectively reversible because it records both original and replacement values. Store it separately from shared results, limit access, and delete it once cross-run consistency is no longer needed.

Mapping vaults are reusable across collections. When loading a vault written by an older version, unusable entries with an empty original or pseudonym are removed automatically and the cleaned vault is saved atomically; every valid mapping and its relationships are retained. Other invalid entries report their entry number and exact validation problem.

The mapping path:

- requires `--pseudonymize`
- must differ from the configured replacements file
- must not equal the main output or any enabled ADX/OpenGraph sidecar path
- can be reused only with compatible configured replacement rules

The same original and entity type receive the same pseudonym. Azure subscription IDs and resource groups also share mappings between standalone columns and structured Resource IDs.

Related account columns are treated as one identity profile within a record. For example, `AccountName`, `AccountUpn`, and `AccountDomain` (including prefixed variants such as `InitiatingProcessAccount*`) receive a shared pseudonymous username and domain even when the original SAM account and UPN local part differ. If a selected identity component such as `AccountUpn` is empty, a context-specific value is synthesized from the same account profile so the output remains complete and internally coherent; the empty string itself is never stored as a global mapping. A device FQDN in the same event uses the primary `AccountDomain` as its suffix, retaining the pseudonymous host label. Those aliases are stored in the vault, so the identity remains stable in later records and collection runs. When a reused vault contains independent mappings created by an older version, the linked aliases are reconciled to the profile's canonical username and domain and the repaired mappings are saved. Email sender address/domain pairs and device hostname/FQDN/domain groups use the same relationship-aware behavior.

## `--pseudonym-fields`

Overrides the built-in field allowlist with a comma-separated list of exact names or wildcard patterns. Environment variable: `PSEUDONYM_FIELDS`.

```bash
./tableDumper \
  --dump-table DeviceProcessEvents \
  --pseudonymize \
  --pseudonym-fields 'AccountName,*FileName,*FolderPath,DeviceName,ResourceGroup'
```

Matching behavior:

- case-insensitive
- ignores spaces, `_`, `-`, and `.` when comparing field names
- supports `*` for any sequence and `?` for one character
- understands one-letter Kusto custom-column suffixes such as `_s` and `_g`
- rejects empty comma entries and unsupported pattern characters

Quote wildcard values so the shell does not expand them as filenames.

This is a complete override, not an addition to the table default. A narrow exact list is safest. Using `'*'` inspects every field and re-enables broad NER and pattern recognition, increasing false positives.

The option is only operational when `--pseudonymize` is enabled. If omitted, a table dump uses its table-specific policy; query mode uses the conservative fallback.

## `--pseudonym-replacements-file`

Loads configured literal word and phrase replacements from JSON. Environment variable: `PSEUDONYM_REPLACEMENTS_FILE`. It requires `--pseudonymize`.

```json
{
  "case_sensitive": false,
  "whole_words": true,
  "replacements": [
    {
      "find": ["Contoso", "Contoso Ltd", "Contoso Corporation"],
      "replace": "Northbridge Group"
    },
    {
      "find": "Project Falcon",
      "replace": "Project Aurora"
    }
  ]
}
```

`find` accepts either one string or a list of aliases. Every alias in a list receives the configured `replace` value. Matching is literal, not regular-expression based, so punctuation such as `.`, `+`, `(`, and `\` has no special meaning.

Defaults:

- `case_sensitive`: `false`
- `whole_words`: `true`

Longer phrases win when rules overlap, and configured replacements take priority over NER and automatic identifier recognition. Unmatched identifiers in the same selected value can still be pseudonymized normally.

Configured matches are also recorded in the mapping vault. Reusing a vault with a different replacement for an existing `find` value is rejected to prevent inconsistent datasets.

See [the complete example replacements file](../examples/pseudonym-replacements.json).

## `--pseudonym-map-retention`

Controls what happens to the mapping vault after a successful collection. Default: `keep`. Retention is non-interactive.

| Value | Behavior |
|---|---|
| `keep` | Preserves the vault. Use this across related table collections. |
| `delete` | Deletes the vault after the collection completes successfully. |

Retention is finalized only after a query or table collection completes. A failure before completion leaves the mapping file available for inspection/recovery.

The program never prompts for a retention decision. Use `delete` explicitly when the vault should be removed after a successful run.

## Consistent multi-table collection

Use one kept map for every related run:

```bash
./tableDumper \
  --dump-table DeviceInfo \
  --output devices.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --pseudonym-map-retention keep

./tableDumper \
  --dump-table DeviceLogonEvents \
  --output logons.json \
  --pseudonymize \
  --pseudonym-map ./collection.pseudonyms.json \
  --pseudonym-map-retention keep
```

Once the collection set is complete, securely remove the vault or run the final collection with `--pseudonym-map-retention delete` if immediate deletion matches your retention policy.

## Structural behavior

Azure Resource IDs retain their path hierarchy. The subscription ID, resource group, and resource-name components are replaced consistently while structural labels, provider namespaces, and resource types remain intact.

File paths preserve separators and directory structure. Usernames following `/Users/`, `/home/`, or `C:\Users\` are replaced consistently. Final filenames are preserved unless `--pseudonymize-filenames` is enabled; when enabled, the extension and the relationship with corresponding filename and command-line fields are retained.

Domain-bearing URL fields replace the domain without changing unrelated path GUIDs, software versions, or query-string data. A host/domain field whose entire value is an IP address is left unchanged by the built-in policy.
