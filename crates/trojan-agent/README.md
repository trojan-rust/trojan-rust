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

Set `metrics.listen` in the panel-supplied service configuration, for example to `127.0.0.1:9090`, to expose the agent's local accounting metrics through the service's `/metrics` endpoint. The agent uses the same Prometheus recorder as the service. Metrics also work when the service starts its recorder after the journal opens. No node IDs, stream IDs, tokens, or error messages become metric labels.

All three managed roles support `metrics.tls` with node-local `cert`, `key`, and `client_ca` paths. Dashboard registration and the local configuration cache preserve these fields. Certificate files must already exist on the node, including during offline startup. See [mutual TLS configuration and verification](../trojan-metrics/README.md#mutual-tls).

The metrics listener belongs to the service and closes with its accepted connections before replacement, including a switch from HTTP to mTLS. The process reuses its Prometheus recorder across restarts. Certificate or bind failures propagate through the service error channel; a `ConfigAck` or `Running` message alone does not prove that a scrape works. Verify the real endpoint.

Dashboard PATCH saves configuration for the next registration; it does not send a live `ConfigPush`. Restart the Agent after saving changed metrics settings. Startup can serve the previous cached configuration until registration succeeds, including cached HTTP when Dashboard has newly saved mTLS settings. Verify the real mTLS endpoint before changing network exposure. Panels that implement `ConfigPush` must set `restart_required=true`; this also forces certificate reload when paths are unchanged. An ordinary reconnect with identical configuration keeps the current listener and certificates. Preserve `cache_dir` and traffic journals. Upgrade the node binary before enabling TLS, because older binaries can ignore unknown fields and continue serving HTTP.

| Metric prefix: `trojan_agent_node_traffic_` | Meaning |
| --- | --- |
| `enabled` | Whether the process records node traffic after capability negotiation. |
| `pending_reports`, `pending_bytes` | Durable reports and their total incoming plus outgoing bytes awaiting acknowledgement. |
| `oldest_pending_timestamp_seconds` | Original observation time of the first queued report; zero when the queue is empty. |
| `last_sample_timestamp_seconds` | Time of the last successful sampler checkpoint, including zero-traffic checkpoints. |
| `operations_total{operation,outcome}` | Attempts with `operation` equal to `sample`, `ack`, or `send`, and `outcome` equal to `success` or `error`. |
| `operation_duration_seconds{operation}` | Duration of those operations, including journal work for samples and acknowledgements. |
| `panel_rejections_total` | Reports explicitly rejected by the panel. |

Calculate backlog age with `clamp_min(time() - trojan_agent_node_traffic_oldest_pending_timestamp_seconds, 0)` and filter for `trojan_agent_node_traffic_pending_reports > 0`. A successful `send` means a report entered the WebSocket sender's queue; only a successful acknowledgement commits removal from the journal. Replayed reports count as additional sends. Failed journal writes leave pending gauges and the last successful sample timestamp unchanged.

The journal uses buffered JSON writes, file synchronization, and atomic replacement. Its existing JSON format, sequence identities, and pending reports remain compatible. Reproduce the durable I/O benchmark with:

```sh
devenv shell -- cargo test -p trojan-agent --release journal_backlog_benchmark -- --ignored --nocapture --test-threads=1
```

The benchmark seeds 100, 1,000, and 10,000 pending reports, measures five samples and five individual acknowledgements per size, and reopens each journal. A local run with 10,000 reports (a 1,229,133-byte journal) measured:

| Operation | Unbuffered writes | Buffered writes |
| --- | ---: | ---: |
| Sample checkpoint | 773.862 ms | 12.484 ms |
| Individual acknowledgement | 583.564 ms | 13.707 ms |
| Journal recovery | 519.418 ms | 12.196 ms |

These timings depend on the host and filesystem. Each save still clones and rewrites the pending queue in O(n) time, and draining an entire backlog with individual acknowledgements still produces O(n²) total encoding and write volume. Buffering removes the measured syscall overhead; it does not make arbitrarily large backlogs constant-cost. Use the operation-duration histogram and backlog gauges to detect when a different storage layout is required.
