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

## Node metrics configuration

The `config` object in `POST /admin/nodes` and `PATCH /admin/nodes/{id}` stores the service JSON, including `metrics.listen` and `metrics.tls.cert`, `key`, and `client_ca`. Dashboard preserves these path strings without reading certificate files or transferring private keys. Paths refer to files on the running node. Provide the complete service configuration when replacing `config`.

PATCH increments the saved configuration version. The Agent receives the saved JSON at its next registration; Dashboard does not send a live `ConfigPush`. Restart the Agent after saving settings that must take effect immediately. Upgrade the node binary before enabling metrics TLS: older binaries can ignore the fields and continue serving HTTP. See [the configuration, Prometheus example, and verification steps](../trojan-metrics/README.md#mutual-tls).

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

Node responses include `period_bytes_in`, `period_bytes_out`, `traffic_used`, `traffic_supported`, `traffic_remaining` (`null` when unlimited or accounting is unsupported), `period_start`, `reset_at`, `online`, and `unavailable_reason` (`disabled`, `offline`, `traffic_unsupported`, `traffic_exhausted`, or `null`). All timestamps are Unix seconds. A calendar edit recalculates the current window from retained history. A monthly reset opens a new window without deleting history, including after dashboard downtime.

The agent protocol remains version 1. Agents offer node accounting with `x-trojan-node-traffic: 1` in the WebSocket request; the dashboard echoes the header in its upgrade response. Only negotiated sessions exchange durable node deltas, acknowledgments, and scheduling snapshots. Legacy agents retain their original registration, heartbeat, and user traffic messages.

The dashboard commits each delta and its stream cursor together before acknowledging the report. Replays do not charge twice. Delayed reports belong to their observation timestamp, so a reporting interval that crosses midnight is charged to the new window. Node accounting does not add charges to user quotas or user traffic logs. Accounting starts with negotiated reports; process-local heartbeat counters are not imported as historical usage.

`traffic_supported` is true only when all live sessions for the node negotiated accounting. A legacy session makes the node's accounting incomplete, even if another session supports reports. Historical numeric totals remain visible; zero received bytes do not mean zero actual usage. An online node with incomplete accounting and a finite quota has reason `traffic_unsupported` and cannot accept managed routes. An unlimited legacy node retains static unlimited availability. When no session is connected, accounting support is unknown and reported as false.

The dashboard sends node availability snapshots to negotiated sessions after reports, policy updates, connections and disconnections, and at monthly resets. A node becomes offline after 90 seconds without a heartbeat. Snapshots expire within 90 seconds and at the next reset boundary. These messages do not change `config_version` or restart services. Quotas govern new connections; existing connections can continue consuming traffic.

### Node observability

Node responses expose `bytes_in_per_second` and `bytes_out_per_second` as the mean forwarded byte rate between two received heartbeats. `rate_interval_seconds` contains the actual monotonic receive interval, not the configured reporting interval. These rates describe recent activity; they do not measure link capacity, latency, or packet loss. The existing `bytes_in` and `bytes_out` fields remain process counters from the most recent heartbeat.

`rate_status` is `current`, `warming_up`, `stale`, `multiple_sessions`, or `offline`. Rates and their interval are `null` unless the status is `current`. The first heartbeat, a counter or uptime reset, and an interval of at least 90 seconds require a new baseline. Connecting or disconnecting a session clears that baseline. More than one live session makes the rate unknown because protocol v1 does not identify each process's counters. `heartbeat_received_at` is the Unix receipt time of the last heartbeat in the current single-session baseline; `heartbeat_age_seconds` uses a monotonic clock. Both are `null` without that baseline, including after dashboard restart or disconnection.

`traffic_last_observed_at` is the newest observation timestamp in accepted durable reports. `traffic_last_received_at` is the receipt time of the most recently accepted report. Replays do not advance either value. An older report from another stream may advance receipt time without advancing observation time. Migrated history has a known observation time and an unknown receipt time. These fields describe reports, not accounting completeness: idle agents send no nonzero delta, and protocol v1 has no backlog-complete watermark. A fresh heartbeat or availability snapshot does not prove that all traffic reports have arrived.

`GET /admin/nodes/{id}/traffic/series?start=1727740800&end=1727827200&bucket=hour` returns directional bytes from the durable node ledger. `start` and `end` are Unix seconds with an inclusive start and exclusive end. `bucket` accepts `minute`, `hour` (default), or `day`. Requests may cover at most 366 days and 2,160 buckets. Buckets align to UTC; the first and last buckets include only samples inside the requested range. Each point has `timestamp`, `bytes_in`, and `bytes_out`. Reports belong to their `observed_at` bucket, including delayed reports, rather than their receipt bucket.

The response identifies `source: "node_traffic"` and `missing_buckets: "unknown"`. Missing buckets are omitted because absent reports cannot distinguish idle traffic from missing accounting. The existing `/admin/traffic`, `/admin/traffic/series`, and `/me/traffic` endpoints continue to represent user settlement. Their totals can differ from node forwarding totals, and adding totals across hops counts the same transfer at each hop.

Node series use the ledger's `(node_id, observed_at)` index and bound the requested range and response size. Original observations remain available for exact calendar-policy recalculation; this endpoint does not prune the ledger. Current quota windows remain cached. Calendar changes and resets rebuild windows in batches of at most 250 nodes, with one indexed scan for both directions. To measure cold rebuilds and warm snapshots against 1, 100, and 1,000 nodes with 1,000 ledger rows each, run `devenv shell -- cargo test -p trojan-dash snapshot_scaling --lib -- --ignored --nocapture`.

On the development host, that benchmark used the debug profile and in-memory SQLite. At 1,000 nodes and 1 million ledger rows, a cold rebuild fell from 1.08 seconds to 0.49 seconds. Mean warm snapshots measured 14.4 milliseconds before and 14.6 milliseconds after, with no demonstrated improvement. These measurements exclude disk durability costs and WebSocket fanout.

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
