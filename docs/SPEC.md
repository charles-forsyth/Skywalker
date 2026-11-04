# Skywalker: specification

| | |
|---|---|
| Spec version | 1.0, 2026-11-04 (first spec; written from the code, README files and the live service) |
| Applies to | skywalker v0.35.0 (pyproject; git tags stop at v0.34.3), MCP `tools_version` 2 |
| Status | CLI: built, used by RC staff. MCP server: live on Cloud Run as an internal pilot. A2A agent: live in the same service. |
| Owner | Chuck Forsyth (Research Computing). Authors: Chuck and Hermes. |
| Repo | https://github.com/charles-forsyth/Skywalker (public, MIT) |
| Nexus | project record "Skywalker MCP Server" (5cc9951a) |

## 1. What Skywalker is

Read-only audit, cost and security reporting for the Ursa Major Google Cloud fleet (the research
GCP projects UCR Research Computing runs). It has two front ends that share one library:

- **CLI** (`skywalker`, `src/skywalker/main.py`): staff tool for audits of one project or the whole
  organization, a fleet performance monitor, the "zombie hunter" for wasted spend, model usage and
  cost, API key review, billing reports, and one write mode (`fix`, Ops Agent install over IAP).
- **MCP server** (`mcp_server/`): 21 read-only tools over `skywalker.intel`, signed in with Google,
  acting as the caller. Clients: Hermes (`skywalker`), Atrium's cloud agent, Telescope (Mac), Ultra.
- **A2A agent** (`mcp_server/agent.py`, `/a2a/`): Gemini agent over the same tools for Gemini
  Enterprise, with the same role checks and audit.

## 2. Layout

| Path | What |
|---|---|
| `src/skywalker/walkers/` | per-service collectors used by the CLI (compute, storage, iam, network, gke, run, sql, filestore, vertex, asset, monitoring, apikeys, modelusage, org) |
| `src/skywalker/modes/` | CLI modes: audit, monitor, zombies, modelusage, apikeys, billing, fix |
| `src/skywalker/intel/` | the MCP library: gcp (read-only HTTP gate), billing, iam, inventory, ops, overview, projects, recommend, security |
| `mcp_server/` | server.py (tools), auth.py (OAuth 2.1), access.py, scope.py, users.py, store.py, cache.py, agent.py, app.py, deploy.sh, Dockerfile |
| `tests/` | 21 files, about 134 tests |
| `docs/` | GitHub Pages showcase (index.html) and this spec |

## 3. Read-only guarantee (MCP and A2A)

- `skywalker/intel/gcp.py` refuses any request that is not a GET or one of three read RPCs
  (`getIamPolicy`, Logging `entries:list`, a single BigQuery `SELECT`) before it leaves the process.
- No write tools exist. The `cloud-platform` scope is requested only because the read-only Google
  scopes do not cover budgets, asset search, IAM, Recommender, quotas or SCC (checked 2026-10-04).
- The service account `skywalker-mcp@ucr-research-computing.iam.gserviceaccount.com` has no Google
  Cloud data roles; every call uses the signed-in person's own token, so Google's audit logs name them.
- The CLI is different: it runs as whoever runs it, and `fix` mode writes (installs the Ops Agent).

## 4. Auth and access (same stack as Nexus MCP and ursa-bifrost)

- OAuth 2.1 + PKCE S256 with dynamic registration; Google sign-in limited to the `users.yaml` domain
  (`hd` checked on the request and in the ID token). Unknown client ids are refused.
- `users.yaml` in Secret Manager, re-read on change. Roles `read` < `staff` < `admin`, checked on
  every call; the tool list is filtered per caller.
- Project scope (`scope.py`): a `read` user may ask only about the projects listed for them (exact
  ids or `prefix*`); staff and admins may ask about any project their Google account can see.
  `skywalker_focus` sets the caller's default project (staff may focus on `all`).
- Google refresh tokens sealed with AES-256-GCM in the store on a Cloud Storage volume; rotating
  refresh tokens bound to the client; `/revoke` (RFC 7009); `/signout` revokes the Google grant.
- One JSON audit line per sign-in and tool call; per-person and per-client rate limits; in-flight
  cap; program clients with a role ceiling. Answers cached per person and client for 120 s.

## 5. Tools (21)

17 `read`: overview, projects, spend, budget, inventory, compute, recommendations, access,
service_accounts, api_keys, exposure, activity, services, api_traffic, quotas, whoami, focus.
4 `staff`: fleet, spend_all, budgets, spend_trend. Full table in `mcp_server/README.md`.
Bump `tools_version` in server.py when a tool is added, removed or changes shape.

## 6. Endpoints

`/mcp` (Streamable HTTP, stateless), `/sse` + `/messages/` (legacy), OAuth discovery and
`/register` `/authorize` `/oauth/callback` `/token` `/revoke`, `/whoami`, `/signout`, `/health`
(rev + tools_version), `/a2a/` and the public agent card at `/a2a/.well-known/agent-card.json`.

## 7. Deployment (as of 2026-11-04)

| | |
|---|---|
| Service | Cloud Run `skywalker-mcp-server`, project `ucr-research-computing`, us-central1, min 1 / max 1 |
| URL | https://skywalker-mcp-server-492106370716.us-central1.run.app/mcp (alias -dsfh6rrlia-uc) |
| Revision | `skywalker-mcp-server-00015-gsw`, `/health` rev 5b7cdc9, tools_version 2 |
| Deploy | `mcp_server/deploy.sh` (gcloud run deploy; env from the configuration table in the MCP README) |
| Agent model | `SKYWALKER_AGENT_MODEL` (Gemini on Vertex, called as the SA; only role aiplatform.user) |
| A2A limits | 300 messages a day per person (`MESSAGES_PER_DAY`), plus the shared per-person rate limits |

## 8. Data handling

Skywalker reads billing export, IAM policy, asset inventory, audit logs, Recommender and SCC
findings. It stores only sealed tokens, focus settings and short-lived per-person caches. No data
level policy is written for the MCP yet (open item). Contract dollar figures are never added to
outputs; spend comes from the billing export.

## 9. Open items

1. Tag v0.35.0 (code is at 0.35.0; the latest tag is v0.34.3).
2. Write a data-level statement for the MCP and A2A answers (what level the outputs carry).
3. The CLI README still calls the tool "Production" and quotes a sample savings figure; align with
   the MCP pilot status when the README is next touched.
4. Remove the deprecated `/sse` transport (it was to stay "for one release").

## Change log

- 2026-11-04 1.0: first spec, from the code, both READMEs, deploy.sh and the live service.
