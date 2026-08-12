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

## Subscriptions

`GET /sub/{name}?pwd=` renders the template `name` for whoever the password
belongs to, and answers with the headers subscription clients read. A template
is text with these placeholders:

| Placeholder | Rendered as |
| --- | --- |
| `{{ pwd }}` | the caller's password |
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

Traffic is summed twice by one accounting event: `traffic_logs` per day, which
is the record of history, and `traffic_hourly` per hour, which is the only
place sub-day resolution exists and is pruned to `hourly_retention_days`. A
chart range picks its source accordingly — 24h and 3d read the hourly table,
anything wider reads the daily one — so the short ranges only describe traffic
recorded since this table appeared.
