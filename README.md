# spyhop

Context-lean CLI that proxies the Orca Security MCP server (`mcp.orcasecurity.io`) for agents calling it through bash.

```
spyhop auth login | status | logout
spyhop tools [name]
spyhop call <tool> --arg key=value ... [--raw]
spyhop search "critical alerts in progress" [--limit 5]
spyhop alert get <id|->            # - reads IDs from stdin
spyhop alert timeline|attack-path <id>
spyhop alert similar <id> --by type|malware|secret [--secret-hash H]
spyhop alert status <id> --to open|in_progress|closed|snoozed|dismissed --yes
spyhop alert comment <id> --body TEXT --yes
spyhop alert snooze <id> --days N [--reason R] [--justification T] --yes
spyhop alert dismiss <id> [--reason R] [--justification T] --yes
spyhop alert score <id> --score 0-10 [--reason R] [--justification T] --yes
spyhop alert verify <id> --yes
spyhop asset get <id> [--model-type AwsEc2Instance]
```

`--json` prints curated JSON; `--raw` prints the MCP result text unchanged.

## Alert writes need `--yes`

`status`, `comment`, `snooze`, `dismiss`, `score` and `verify` change the tenant. Without `--yes` nothing is sent: stdout gets `{"tool":...,"args":...}`, stderr says `pass --yes to execute`, and the exit code is 2. With `--yes` the unwrapped result prints (as with `call`). `--reason` matches the tool's enum case-insensitively and is sent in canonical form; completion offers the values. `alert status` used to execute without `--yes`.

## Composition

- `alert get -` / `asset get -` read IDs from stdin (one per line). Text records are separated by blank lines, `--json` prints NDJSON; a failing ID prints `<id>: <error>` to stderr, the run continues, and the exit code is the first failure's.
- `search "..." --ids` prints only `AlertId` / `asset_unique_id`, one per line.
- `--fields a,b,c` selects top-level fields in the order given (missing values omitted; empty cells in TSV).
- `--format text|json|tsv` (`--json` is an alias for `--format json`). TSV has a header row and no footer.
- `--raw` cannot be combined with `--fields`, `--format`, `--json` or `--ids`; `--ids` cannot be combined with `--fields`, `--format` or `--json`.

```bash
spyhop search "critical alerts in progress" --ids | spyhop alert get - --fields AlertId,Title --format tsv
```

## Finding tools and tab completion

- `spyhop tools --grep alert --grep similar` keeps tools whose name or description contains every term (case-insensitive); no match exits 1.
- The tool list is cached for 24h in `~/.cache/spyhop/tools-<hash>.json` (override the dir with `SPYHOP_CACHE_DIR`; OAuth and token modes and endpoints get separate files). `tools --refresh` refetches; `call` always talks to the server. `auth logout` removes the cache.
- Completion covers tool names, `--arg` keys (`key=`), and the fixed values of `--to`, `--region` and `--format`. It never prompts or opens a browser, and falls back to a stale cache when the server is unreachable.

```bash
source <(spyhop completion zsh)    # or: bash, fish, powershell
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
