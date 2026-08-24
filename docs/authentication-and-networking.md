# Authentication and networking

Defender XDR queries use Microsoft Graph credentials. Direct Azure Data Explorer uploads use a separate set of ADX credentials described in [Azure Data Explorer](azure-data-explorer.md#adx-authentication-flags). BloodHound has its own authentication flags.

## `--auth`

Selects token acquisition for Microsoft Graph and ADX actions. Default: `auto`.

| Value | Behavior |
|---|---|
| `auto` | Uses service-principal auth when all three credentials for the current target are present; otherwise calls Azure CLI. |
| `sp` | Requires the complete tenant ID, client ID, and client secret set for the current target. |
| `azcli` | Calls `az account get-access-token` and requires a prior `az login`. |
| `none` | Skips token acquisition and omits the `Authorization` header. Use only with an endpoint intentionally configured for anonymous access. |

The "current target" distinction matters: Defender/Graph uses `--tenant-id`, `--client-id`, and `--client-secret`; ADX uses their `--adx-*` equivalents. Graph credentials are not silently reused for ADX.

With `auto`, partially configured service-principal credentials do not produce a hybrid mode; the tool falls back to Azure CLI. Use `--auth sp` when incomplete credentials should fail immediately.

For an anonymous ADX-compatible endpoint, including one served over plain HTTP, select `--adx-auth none`. This ADX-specific override lets a combined collection-and-upload run continue to use `--auth azcli` or `--auth sp` for Microsoft Graph. When `--adx-auth` is omitted, ADX inherits `--auth`. Plain HTTP does not protect uploaded data in transit, so limit it to trusted networks or local development.

## `--tenant-id`

Sets the Microsoft Entra tenant for Defender/Graph authentication. Environment variable: `AZURE_TENANT_ID`.

For service-principal auth it is part of the OAuth token URL. For Azure CLI auth it is passed to `az account get-access-token --tenant`, allowing a tenant other than the CLI's current default.

## `--client-id`

Sets the application/client ID for Defender/Graph service-principal authentication. Environment variable: `AZURE_CLIENT_ID`. It is ignored by Azure CLI auth.

## `--client-secret`

Sets the secret for Defender/Graph service-principal authentication. Environment variable: `AZURE_CLIENT_SECRET`. It is ignored by Azure CLI auth.

Avoid putting secrets directly in shell history or process arguments. Prefer the process environment, a protected dotenv file, or a dedicated secret-injection mechanism. The tool does not write credential values into result files.

## `--endpoint`

Sets the Microsoft Graph API base URL used for advanced hunting requests. Default: `https://graph.microsoft.com/v1.0`.

The tool appends the security hunting route to this base. Override it only for a compatible sovereign-cloud endpoint, proxy, or test server. A trailing slash is removed automatically. The OAuth audience does not change with this flag; set `--resource` separately when required.

## `--resource`

Sets the OAuth resource/audience requested for Defender/Graph tokens. Default: `https://graph.microsoft.com`.

This value is sent in the service-principal token request and passed to `az account get-access-token --resource`. Keep it aligned with `--endpoint`, especially in sovereign clouds. A trailing slash is removed automatically.

## `--login-base-url`

Sets the Microsoft Entra login base used for service-principal token requests. Default: `https://login.microsoftonline.com`.

The token URL is formed as:

```text
<login-base-url>/<tenant-id>/oauth2/token
```

This setting affects both Graph and ADX service-principal token requests. Azure CLI authentication manages its own login endpoints. A trailing slash is removed automatically.

## `--env-file`

Selects the dotenv file used to supply supported flag defaults. Default: `.env`.

If the default `.env` does not exist, it is silently ignored. A missing explicitly selected file is an error. Supplying an empty path disables dotenv loading.

Supported syntax is intentionally small:

```dotenv
# comments and blank lines are ignored
export AZURE_TENANT_ID="tenant-id"
AZURE_CLIENT_ID=client-id
AZURE_CLIENT_SECRET='secret-value'
```

The loader supports `KEY=VALUE`, optional `export `, and matching single or double quotes. It does not perform shell expansion, command substitution, multiline parsing, or variable interpolation.

Only flags explicitly wired to environment variables read values from this file:

- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- `ADX_CLUSTER`, `ADX_DATABASE`, `ADX_AUTH`, `ADX_TENANT_ID`, `ADX_CLIENT_ID`, `ADX_CLIENT_SECRET`, `ADX_RESOURCE`
- `BLOODHOUND_URL`, `BLOODHOUND_TOKEN`, `BLOODHOUND_TOKEN_ID`, `BLOODHOUND_TOKEN_KEY`
- `PSEUDONYM_FIELDS`, `PSEUDONYM_REPLACEMENTS_FILE`

Explicit flags override the process environment; the process environment overrides dotenv values.

## `--timeout`

Sets the timeout on the shared in-process HTTP client. Default: `60s`.

The value uses Go duration syntax, for example `500ms`, `30s`, `2m`, or `1m30s`. It applies independently to Microsoft Entra service-principal token requests, Graph calls, ADX calls, and BloodHound calls. It does not configure the Azure CLI's own network timeout.

Choose a value large enough for ADX ingestion and large Graph hunting responses. A timeout aborts the current HTTP request; it does not resume or retry that request automatically.

## `--insecure-skip-verify`

Disables TLS certificate-chain and hostname verification for HTTPS requests made by the application. Default: `false`.

This affects the shared HTTP client, including service-principal token requests, Graph, ADX, and BloodHound. It does not alter Azure CLI TLS behavior.

Use it only for a controlled test system or a self-signed internal endpoint whose certificate cannot yet be trusted properly. It makes man-in-the-middle attacks possible and should not be used as a routine production setting.

## Authentication examples

Azure CLI:

```bash
az login
./tableDumper --auth azcli --query 'DeviceInfo | take 10'
```

Service principal from the environment:

```bash
export AZURE_TENANT_ID='<tenant-id>'
export AZURE_CLIENT_ID='<application-id>'
export AZURE_CLIENT_SECRET='<secret>'

./tableDumper --auth sp --query-file queries/device-info.kql
```

The Graph application needs the Microsoft Graph `ThreatHunting.Read.All` application permission with administrator consent for service-principal query mode.
