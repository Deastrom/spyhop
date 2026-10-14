# spyhop

Context-lean CLI that proxies the Orca Security MCP server (`mcp.orcasecurity.io`) for agents calling it through bash.

```
spyhop auth login | status | logout
spyhop tools [name]
spyhop call <tool> --arg key=value ... [--raw]
spyhop search "critical alerts in progress" [--limit 5]
spyhop alert get <id> | alert status <id> --to open|in_progress|closed|snoozed|dismissed
spyhop asset get <id> [--model-type AwsEc2Instance]
```

`--json` prints curated JSON; `--raw` prints the MCP result text unchanged.

## Composition

- `alert get -` / `asset get -` read IDs from stdin (one per line). Text records are separated by blank lines, `--json` prints NDJSON; a failing ID prints `<id>: <error>` to stderr, the run continues, and the exit code is the first failure's.
- `search "..." --ids` prints only `AlertId` / `asset_unique_id`, one per line.
- `--fields a,b,c` selects top-level fields in the order given (missing values omitted; empty cells in TSV).
- `--format text|json|tsv` (`--json` is an alias for `--format json`). TSV has a header row and no footer.
- `--raw` cannot be combined with `--fields`, `--format`, `--json` or `--ids`; `--ids` cannot be combined with `--fields`, `--format` or `--json`.

```bash
spyhop search "critical alerts in progress" --ids | spyhop alert get - --fields AlertId,Title --format tsv
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | error, including not found |
| 2 | usage error (bad flag, value or combination) |
| 4 | unauthorized (`spyhop auth login`, or check `ORCA_TOKEN`) |

## Auth

- Default: OAuth 2.1 (`spyhop auth login`, tokens in `~/.config/spyhop/tokens.json`).
- `ORCA_TOKEN` set: API token auth against `api.<region>.orcasecurity.io/mcp` (`ORCA_REGION` or `--region`: us, eu, au, in, sa).
- `SPYHOP_MCP_URL` overrides the MCP endpoint.

Install: `mise use github:Deastrom/spyhop`.
