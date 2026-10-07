# Network benchmark

Measure the shared relay over real TCP sockets and the complete Trojan-over-TLS server. The load generator and echo target run in the parent process. The measured server runs in a fresh child process for each case. Both server paths record Prometheus counters and node totals.

The benchmark explicitly enables destination metrics to retain the initial baseline's recording cost when server defaults change.

```sh
cargo bench -p trojan-server --bench network --locked -- \
  --label baseline --connections 1,32,128 --seconds 3 --repeats 3 \
  > /tmp/trojan-network-baseline.jsonl
```

Use Rust stable. Install `rustfmt` and `clippy` to run the repository checks. On Ubuntu 24.04, install the native build dependencies:

```sh
sudo apt-get install build-essential cmake perl pkg-config libclang-dev libsqlite3-dev libssl-dev
```

The benchmark does not require Nix. If you use the repository's devenv environment, prefix the Cargo command with `devenv shell --`.

For a Linux VM, run the benchmark inside the guest. Keep the source and build directory on the guest's local disk. The load generator, server, and echo target must share the guest's loopback network. Record the Rust version and VM resources with the results. Keep both the guest and the host free of concurrent builds and other load during measurements.

Use `--transports tcp` or `--transports tls` to select one path. Use `--workers` to set the worker count in each process. Use `--buffer-bytes` to vary the relay buffer size. Keep these values constant when comparing implementations. Run measurements without concurrent builds or other load.

Each case establishes all connections and exchanges eight buffer-sized messages per connection before measurement. The benchmark then runs two phases:

- Latency: each connection has one outstanding request. The default payload is 512 bytes. P99 uses the nearest rank over all completed round trips. This closed-loop distribution does not estimate latency under a fixed external arrival rate.
- Bulk: each connection sends continuously while a separate future receives echoed bytes. The default write size is 32 KiB. Reported throughput counts both directions, so divide by two for one-way payload throughput. The timed interval includes draining the final bytes and closing the connections.

The benchmark rejects mismatched payloads, missing bytes, connection failures, and stalled I/O. P99 excludes connection setup and TLS handshakes. The TLS client verifies the temporary server certificate. DNS uses a literal loopback destination; HTTP authentication, routing rules, WebSocket, and metrics scraping are not part of this baseline.

Output is JSON Lines. CPU usage is the child process's accumulated CPU time difference divided by elapsed wall time; 100% represents one occupied CPU. RSS is the child process's resident memory. Per-connection RSS is the difference between the warmed idle process and the process holding all warmed connections, divided by the connection count. Allocator reuse and page residency affect this estimate, especially at low connection counts. Kernel socket memory is excluded. Peak RSS is sampled every 200 ms during bulk transfer.

Use the same machine, toolchain, worker count, payload sizes, and matrix for before/after measurements. Compare repeated runs rather than a single sample. Loopback results identify local CPU and memory costs; they do not predict WAN throughput or Linux behavior from a macOS run.
