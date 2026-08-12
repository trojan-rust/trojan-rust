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
| `GET /sub/{name}`, `GET /me` | users |

Node calls answer with an encoded `Result` under HTTP 200 — a rejected user is
an answer, not a transport failure. `/admin/*` answers `{"error": "..."}` with
a status: 409 when a name is taken, 401 when the token is wrong.

## Schema

Migrations run at startup. `m_001_init` carries the name and shape used by the
panel this service succeeds, so a database that panel created is recognised as
already migrated rather than re-created; `m_002_agent_columns` adds the columns
the agent socket needs. Pointing this service at such a database applies only
the second, and leaves every row alone.
