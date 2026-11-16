# Skywalker MCP server

"What is happening in my Google Cloud project?" as MCP tools, for Claude, Gemini
Enterprise, Hermes and programs such as Ultra. Built on `skywalker.intel` in this repo.

## Design

- **Acts as the caller.** Sign-in asks Google for the `cloud-platform` scope with
  offline access. Each person's Google refresh token is sealed (AES-256-GCM) in the
  store, and every tool call runs on that person's own access token. A person sees
  exactly what their Google account can see, and Google's audit logs name them. The
  server's service account has **no Google Cloud data roles**.
- **Read-only, enforced in code.** `skywalker/intel/gcp.py` refuses every request
  that is not a GET or one of three read RPCs (`getIamPolicy`, Logging
  `entries:list`, a single BigQuery `SELECT`), before it leaves the process. There
  are no write tools. The broad scope is needed only because the read-only Google
  scopes do not cover budgets, asset search, IAM, Recommender, quotas or Security
  Command Center (checked against each API's discovery document, 2026-10-04).
- **Same auth stack as the Nexus MCP server and ursa-bifrost.** Google sign-in limited
  to the domain in `users.yaml` (`hd` on the request and re-checked in the ID
  token); users file with roles in Secret Manager, re-read on change; roles checked
  on every call; tool list filtered per caller; opaque access/refresh tokens stored
  hashed and sealed on a Cloud Storage volume (restarts keep everyone signed in);
  rotating refresh tokens bound to the client and a `grant_id` family (90-day max
  age, replay revokes the whole grant, `/revoke` revokes both access and refresh
  tokens); canonical `SKYWALKER_PUBLIC_URL` pinned from env (`X-Forwarded-Host`
  ignored); CSRF-protected `POST /authorize` confirmation with 90-day
  `Path=/authorize` seen cookies scoped per `(client_id, redirect_host)` for
  program clients only (dynamic RFC 7591 clients always show the consent screen);
  one JSON audit line per sign-in and tool call; per-person and per-client rate
  limits; an in-flight cap; program clients with a role ceiling; CORS restricted
  to `/.well-known/*`. Unknown `client_id`s are refused (no adoption), and a
  redirect URI must be registered.
- **Answers cached per person and client** for 120 s (`fresh=true` skips the cache).
  Nothing is shared between people.
- **Streamable HTTP** at `/mcp` (stateless). The deprecated SSE transport at `/sse`
  stays for one release.
- **Project scope** (`scope.py`). Each person in `users.yaml` has `projects` (exact
  ids, or prefixes ending in `*`). A `read` user may ask only about those; a call
  naming any other project is refused before Google is asked, even if their own
  Google account could see it, and `skywalker_projects` lists only theirs. Staff and
  admins may ask about any project their Google account can see. `project_id` is
  optional on every per-project tool and defaults to the caller's **focus**: their
  first listed project, changed with `skywalker_focus` (sealed in the store, shared
  by all their clients). Staff can focus on `all`, which makes `skywalker_overview`
  the fleet view. For `read` users whose Google accounts lack central Cloud Billing
  IAM, optional `project_allocations` / per-user `allocations` in `users.yaml` and
  `SKYWALKER_PROJECT_USAGE_FILE` synthesize monthly allocation and usage summaries
  scoped strictly to `project_allowed`.
- **Atrium brokered assertions (`atr1.*`) and A2A consolidation.** External A2A lives
  exclusively on Atrium Concierge (standalone `/a2a/` is unmounted). Atrium calls
  `/mcp` with short-lived `atr1.*` ECDSA P-256 SHA-256 assertions verified against
  `ATRIUM_BROKER_PUBKEY` (fail-closed if unset), `ATRIUM_BROKER_ISSUER`, and
  `ATRIUM_BROKER_AUDIENCE` / `<base_url>/mcp`, bounded to `0 < exp - iat <= 360` with
  `+/-30 s` clock skew. The assertion's `cid` must match a pre-registered, non-disabled
  `program_client` in `users.yaml` (e.g. `skywalker-atrium`), enforcing the exact same
  `min(user_role, client.max_role)` ceiling, per-program `calls_per_min` budget,
  caller-scoped Google token lookup, and `via: "program:<cid>"` audit fields as OAuth.

## Endpoints

| Path | What |
|---|---|
| `/` | RC-styled browser landing page (`Accept: text/html`); 401 challenge for programmatic probes |
| `/mcp` | MCP, Streamable HTTP (needs an OAuth token or `atr1.*` brokered assertion) |
| `/sse`, `/messages/` | MCP, legacy SSE (needs a token) |
| `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server` | discovery |
| `/register`, `/authorize` (GET/POST), `/oauth/callback`, `/token`, `/revoke` | OAuth 2.1 (PKCE S256) |
| `/whoami` | identity, role, whether a Google token is stored |
| `/signout` (POST) | delete and revoke your Google grant and end all your sessions |
| `/health` | `rev` (commit) and `tools_version` |

## Tools

All are read-only (`readOnlyHint`). `read` = anyone on the list; `staff` costs more
to run (whole billing account or every project).

| Tool | Role | What it answers |
|---|---|---|
| `skywalker_overview` | read | One call: findings first (alerts, warnings, notes), then spend and 7-day trend, budget, VMs/GPUs, idle disks/IPs, APIs and traffic, IAM risks, exposure, SCC, API keys, admin changes. `deep=true` adds Recommender and SA keys |
| `skywalker_projects` | read | projects you can see; find an id by name or label |
| `skywalker_spend` | read | billing export: gross, credits, net by service, SKU, day or region; month to date, last N days, or a month |
| `skywalker_budget` | read | the project's budget(s) vs this month's spend, daily rate, throttle topic |
| `skywalker_inventory` | read | Cloud Asset Inventory counts by type and location (every region); list one type |
| `skywalker_compute` | read | VMs, GPUs, spot, external IPs, days stopped; disks (unattached first), IPs, snapshots, images |
| `skywalker_recommendations` | read | Recommender: idle VM/disk/IP/image, rightsizing, Cloud SQL, commitments, unattended project, unused IAM roles, with monthly savings |
| `skywalker_access` | read | IAM policy with risky grants flagged (public, outside domain, deleted, admin roles, default SA as editor) |
| `skywalker_service_accounts` | read | service accounts, user-managed keys and their age, last authentication (Policy Analyzer) |
| `skywalker_api_keys` | read | API keys, restrictions, requests per key (key strings never read) |
| `skywalker_exposure` | read | public IAM bindings, open admin ports, VMs with external IPs, SCC findings |
| `skywalker_activity` | read | Admin Activity audit log: who changed what |
| `skywalker_services` | read | enabled APIs, costly ones first |
| `skywalker_api_traffic` | read | requests and errors per API, or per method for one API (Gemini vs Claude on Vertex) |
| `skywalker_quotas` | read | quota usage vs limit, near-limit regions, GPU quotas |
| `skywalker_whoami` | read | who you are, role, Google token health, focus |
| `skywalker_focus` | read | show or set your default project (staff: any, or `all`); changes only a Skywalker setting |
| `skywalker_fleet` | staff | every project: spend leaders, risers, budgets over 100%, unbudgeted spenders, running VMs, public access |
| `skywalker_spend_all` | staff | spend across the billing account by project, service, SKU, day, region, lab label |
| `skywalker_budgets` | staff | every budget with this month's % (over / warn / unbudgeted) |
| `skywalker_spend_trend` | staff | 7 days vs the 7 before, per project, plus account-level charges |

Google's own remote MCP servers (Cloud Billing, Asset Inventory, IAM, API Keys,
Recommender, Monitoring, Logging, Quotas; see
https://docs.cloud.google.com/mcp/supported-products) expose the raw APIs one call
per tool. Skywalker is the layer above them: one call per question, joined across
APIs and the billing export, with findings, limits and per-person caching.

## Configuration

Server settings (env, set by `deploy.sh` from `~/.config/skywalker/mcp-server.env`):

| Variable | Example | Use |
|---|---|---|
| `SKYWALKER_BILLING_TABLE` | `proj.dataset.gcp_billing_export_v1_...` | Billing export (never a caller argument) |
| `SKYWALKER_BILLING_ACCOUNT` | `XXXXXX-XXXXXX-XXXXXX` | Budgets |
| `SKYWALKER_JOB_PROJECT` | `my-project` | where BigQuery jobs run and bill |
| `SKYWALKER_FLEET_SCOPES` | `folders/123,folders/456` | where `skywalker_fleet` searches |
| `SKYWALKER_QUOTA_PROJECT` | `my-project` | quota project for API calls (needs Recommender, Policy Analyzer and Cloud Quotas enabled) |
| `SKYWALKER_MAX_BYTES` | `10737418240` | per-query BigQuery byte cap (default 10 GB) |
| `SKYWALKER_BASE_URL` | `https://skywalker-...run.app` | default public URL when `SKYWALKER_PUBLIC_URL` is unset |
| `SKYWALKER_PUBLIC_URL` | `https://skywalker-...run.app` | canonical OAuth issuer/callback base URL (`X-Forwarded-Host` ignored) |
| `SKYWALKER_PROJECT_USAGE_FILE` | `/data/project_usage.json` | optional pre-aggregated monthly project usage JSON for `read` fallback |
| `ATRIUM_URL` | `https://atrium.example.edu/` | optional Atrium link on public HTML pages |
| `ATRIUM_BROKER_PUBKEY` | `BPk1yj...` | 65-byte uncompressed P-256 SEC1 verification key (base64url) for `atr1.*` brokered assertions; fails closed if unset |
| `ATRIUM_BROKER_ISSUER` | `https://atrium-staging-...run.app` | expected `iss` for `atr1.*` assertions |
| `ATRIUM_BROKER_AUDIENCE` | `https://skywalker-mcp-server-...run.app/mcp` | canonical `aud` for `atr1.*` assertions (accepted alongside `<base_url>/mcp`) |

Every billing query filters on the export's partition column and sets
`maximumBytesBilled`; a month-to-date project query scans about 40 MB.

Who may sign in: `users.yaml` (start from `users.example.yaml`), stored in Secret
Manager as `skywalker-mcp-users`. A person also needs the Google Cloud access they
want to see (project viewer, Billing Account Viewer for budgets and the billing
export, Security Center viewer for SCC findings).

## Deploy

```bash
mcp_server/deploy.sh
```

It refuses uncommitted code, validates `users.yaml`, creates (idempotently) the
service account `skywalker-mcp@`, the bucket and the seal key, uploads the users
file when it changed, copies `src/skywalker/intel` into the image, stamps
`SKYWALKER_REV`, and deploys with min 1 / max 1 instances (always warm; one
instance keeps single-use codes single use).

## Test

```bash
scripts/test_mcp.sh                 # fake Google, fake Cloud; real MCP transport, OAuth 2.1 and atr1.* assertions
uv run python scripts/mcp_mutation_check.py   # every guard must make a test fail
```

Live: `mcp_server/examples/live_client.py login|whoami|tools|call <tool> '<json>'`.

## Clients

- Claude Code: `claude mcp add --transport http skywalker <URL>/mcp`
- Hermes: `hermes mcp add skywalker --url <URL>/mcp --auth oauth` (run alone, then restart)
- claude.ai: add a custom connector with `<URL>/mcp`.
- Atrium Concierge: calls `<URL>/mcp` with `atr1.*` brokered assertions (`cid: skywalker-atrium`) and serves all external A2A traffic.

## Gemini Enterprise

External A2A agents are consolidated onto **Atrium Concierge** (register Atrium's A2A
card in Gemini Enterprise rather than pointing A2A directly at Skywalker). To connect
Gemini Enterprise's own assistant directly to Skywalker as a **Custom MCP data store**,
use the confidential program client in `users.yaml`:

```yaml
clients:
  - id: skywalker-gemini-enterprise
    name: Gemini Enterprise
    max_role: admin            # a person's own role still applies (a read user stays read)
    calls_per_min: 120
    client_secret_sha256: <sha256 of the secret>   # the secret itself goes in GE's form
    redirect_uris:
      - https://vertexaisearch.cloud.google.com/oauth-redirect
      - https://vertexaisearch.cloud.google.com/static/oauth/oauth.html
```

**Custom MCP data store: Gemini's own assistant calls the tools.** Pre-GA; an org
admin must first turn off the constraint "Disable custom MCP server connector for
Gemini Enterprise" and allow the egress host. Data stores > Create > Custom MCP
Server: server URL `<URL>/mcp`, authorization URL `<URL>/authorize`, token URL
`<URL>/token`, client ID and secret as above, scope `mcp`, PKCE on. Then Actions >
Reload custom actions and enable the Skywalker tools.

Public cloud regions: Skywalker answers only to its own tokens, so Gemini Enterprise
needs no extra Cloud Run invoker grant (the service is public; sign-in is the gate).
