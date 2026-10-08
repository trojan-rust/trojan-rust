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

Node accounting is an optional protocol v1 capability. The agent sends `x-trojan-node-traffic: 1` during the WebSocket upgrade and enables accounting only when the panel echoes the same value. Older panels keep the existing forwarding, heartbeat, and user traffic behavior. The agent sends no node reports and creates no new report backlog while connected to an older panel. Enabling accounting drains and restarts the service, closing existing connections during this one-time transition. The transition excludes all earlier traffic from node reports and requires a fresh node-state snapshot for managed entries. Reconnecting with the same capability and configuration preserves the service and existing connections.

Node quota accounting uses `node-traffic.json` in `cache_dir`. The agent checkpoints deltas at the report interval, including while disconnected, and retains each delta until the panel acknowledges a committed report. Reconnection and restart replay the original sequence and observation time, so the panel can reject duplicates and charge the original billing period. Shutdown closes the service's connections before the final checkpoint. Server connections can drain for up to 30 seconds; a configuration push can set a shorter drain timeout. Entry and relay shutdown closes existing connections immediately. Heartbeat totals remain live diagnostics. Node traffic and user traffic are separate accounts.

The node traffic sample interval defaults to the panel setting, or 30 seconds before registration. Set `report_interval_secs` to a positive value to override the interval. Heartbeats run at least every 30 seconds, even when the node sample interval is longer. User traffic batches retain the configured interval. Accounting assigns each sample to the billing period containing the sample timestamp. An abrupt process or host failure can lose bytes collected since the last checkpoint. Existing connections continue when a node reaches its quota; limits affect new connections. Managed entries require a fresh node-state snapshot before admitting connections after startup, and state updates do not restart the service. Legacy configuration caches without an authenticated node ID require registration before startup.

The journal requires writable persistent storage and one agent process per cache directory. Corrupt journals, storage failures, and changed panel or node identities stop the agent explicitly. If sampling or the accounting protocol fails, the agent closes connections immediately without a drain period. Bytes that the failed checkpoint could not save remain uncommitted. The cache and journal remember negotiated accounting support for offline startup. Once accounting has been enabled, rolling the Dashboard back to an older version stops the agent; quotas cannot silently become unenforced. Restore a Dashboard that supports accounting to resume service. Pending reports remain intact. After token rotation, the agent requires successful registration for the same node before starting cached services or replaying reports; the stream and pending reports remain unchanged. To move the agent to a different panel or node, stop new traffic, let the original agent settle pending reports, and shut down the agent. Confirm that the journal's `pending` array is empty, preserve the original cache directory, and configure a new `cache_dir` for the new identity. Do not delete a journal with pending reports.

Server nodes use the same authentication settings as `trojan server`. When `auth.http_url` is set, HTTP handles authentication and user traffic accounting. The agent socket still reports node statistics, but does not report those user bytes again. Graceful shutdown flushes pending HTTP traffic reports.
