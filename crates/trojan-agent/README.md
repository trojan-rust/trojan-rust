# trojan-agent

Run a panel-managed server, entry node, or relay node:

```sh
trojan agent -c agent.toml
```

```toml
panel_url = "wss://panel.example.com/ws/agent"
token = "node-token"
cache_dir = "/var/cache/trojan"
```

The agent starts from cached configuration when available and reconnects to the panel in the background. Panel disconnections preserve the running service, connections, and traffic counters. Changed configurations restart the service after draining the previous service. Configuration pushes that change settings must set `restart_required`; unsupported hot reload requests receive a negative acknowledgement.

Server nodes use the same authentication settings as `trojan server`. When `auth.http_url` is set, HTTP handles authentication and user traffic accounting. The agent socket still reports node statistics, but does not report those user bytes again. Graceful shutdown flushes pending HTTP traffic reports.
