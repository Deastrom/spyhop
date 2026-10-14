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

## Auth

- Default: OAuth 2.1 (`spyhop auth login`, tokens in `~/.config/spyhop/tokens.json`).
- `ORCA_TOKEN` set: API token auth against `api.<region>.orcasecurity.io/mcp` (`ORCA_REGION` or `--region`: us, eu, au, in, sa).
- `SPYHOP_MCP_URL` overrides the MCP endpoint.

Install: `mise use github:Deastrom/spyhop`.
