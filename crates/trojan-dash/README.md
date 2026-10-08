# trojan-dash

The dashboard behind a trojan deployment: users and their quotas, node tokens,
traffic accounting, and subscription links. It is the other end of
`trojan-auth`'s HTTP backend — a node with `http_url` configured talks to this
service — and of the agent socket, which managed nodes connect to instead.

Storage is SQLite. The web panel lives in its own repository and is served from
`static_dir` as static files, so the browser needs no CORS exemption.

## Usage

```bash
trojan dash -c dash.toml
```

See [`dash.example.toml`](dash.example.toml) for the settings, and
[`contrib/trojan-dash.service`](../../contrib/trojan-dash.service) for a unit
file.

Library callers may pass a bound `tokio::net::TcpListener` to `run_with_listener(config, listener, shutdown)`. The listener determines the bound address; `config.listen` is not used. This preserves the reserved port during startup.

`/admin/*` is guarded by a bearer token, read from `TROJAN_DASH_ADMIN_TOKEN` if
set and from `admin_token` otherwise. Prefer the environment: the config file
sits next to the panel directory a backup may copy. The unit reads it from a
root-only `/etc/trojan/dash.env`. Startup fails when neither supplies one.

## What it serves

| Path | Caller |
| --- | --- |
| `POST /verify`, `POST /traffic`, `POST /traffic/chain` | nodes, over `trojan_auth::protocol` |
| `GET /ws/agent` | managed nodes running `trojan agent` |
| `/admin/*` | the operator, with a bearer token |
| `GET /sub/{name}`, `GET /me`, `GET /me/traffic` | users |
| `GET /surge/panel.js` | the script a user's Surge panel runs |

Node calls answer with an encoded `Result` under HTTP 200 — a rejected user is
an answer, not a transport failure. `/admin/*` answers `{"error": "..."}` with
a status: 409 when a name is taken, 401 when the token is wrong.

User updates invalidate cached verification data. The next verification reloads
the user and all node quotas.

## Node quotas

`POST /admin/nodes` and `PATCH /admin/nodes/{id}` accept a node's monthly allowance independently of user allowances:

```json
{
  "traffic_limit": 1099511627776,
  "reset_day": 15,
  "reset_timezone": "Asia/Shanghai"
}
```

`traffic_limit` counts incoming plus outgoing forwarded bytes; zero means unlimited. The default reset is local midnight on day 1 in `UTC`. `reset_day` accepts 1–31 and uses the last day of shorter months. `reset_timezone` accepts an IANA timezone. A repeated midnight uses its first occurrence; a missing midnight advances across the DST gap. Timezone data is included in the binary.

Node responses include `period_bytes_in`, `period_bytes_out`, `traffic_used`, `traffic_remaining` (`null` when unlimited), `period_start`, `reset_at`, `online`, and `unavailable_reason` (`disabled`, `offline`, `traffic_exhausted`, or `null`). All timestamps are Unix seconds. A calendar edit recalculates the current window from retained history. A monthly reset opens a new window without deleting history, including after dashboard downtime.

Protocol version 2 agents send ordered durable node deltas. The dashboard commits each delta and its stream cursor together before acknowledging the report. Replays do not charge twice. Delayed reports belong to their observation timestamp, so a reporting interval that crosses midnight is charged to the new window. Node accounting does not add charges to user quotas or user traffic logs. Accounting starts with version 2 reports; process-local heartbeat counters are not imported as historical usage.

The dashboard sends node availability snapshots after reports, policy updates, connections and disconnections, and at monthly resets. A node becomes offline after 90 seconds without a heartbeat. Snapshots expire within 90 seconds and at the next reset boundary. These messages do not change `config_version` or restart services. Quotas govern new connections; existing connections can continue consuming traffic. Upgrade agents and the dashboard together because version 1 registrations are rejected.

## Subscriptions

`GET /sub/{name}?pwd=` renders the template `name` for whoever the password
belongs to, and answers with the headers subscription clients read. A template
is text with these placeholders:

| Placeholder | Rendered as |
| --- | --- |
| `{{ pwd }}` | the caller's password |
| `{{ pwd_url }}` | the same, percent-encoded — what a URL in the template needs, since a generated password is base64 and a raw `+` arrives as a space |
| `{{ username }}` | their username |
| `{{ basic_auth }}` | base64 of `username:password` — the credential `/me` takes |
| `{{ name }}` | the template's own name |
| `{{ update_interval_seconds }}`, `{{ update_interval_hours }}` | its update interval |

### Surge panel

`GET /surge/panel.js` serves a script that draws quota, recent usage and expiry
into a Surge information panel, which needs Surge iOS 4.9.3+ or Mac 5.7.5+. Store
[`templates/surge-panel.sgmodule`](templates/surge-panel.sgmodule) as a template
with the dashboard's own address filled in and no filename, and the user's `/sub`
URL installs as a Surge module. The script reads `/me` with the credential the
template rendered into it, so there is nothing further to hand out, and it
follows Surge's UI language.

## Schema

Migrations run at startup. `m_001_init` carries the name and shape used by the
panel this service succeeds, so a database that panel created is recognised as
already migrated rather than re-created; `m_002_agent_columns` adds the columns
the agent socket needs, and `m_003_hourly_traffic` the rollup below. Pointing
this service at such a database applies only the later ones, and leaves every
row alone.

`m_005_node_traffic` adds independent node observations, reporting cursors, and monthly policies. Cached period counters are updated in the reporting transaction and rebuilt from observations only when the billing window changes. Node history is retained until the node is deleted. Each node's lifetime combined count is bounded by SQLite's signed 64-bit integer range; a report that exceeds the bound is rejected without advancing its cursor.

Traffic is summed twice by one accounting event: `traffic_logs` per day, which
is the record of history, and `traffic_hourly` per hour, which is the only
place sub-day resolution exists and is pruned to `hourly_retention_days`. A
chart range picks its source accordingly — 24h and 3d read the hourly table,
anything wider reads the daily one — so the short ranges only describe traffic
recorded since this table appeared.
