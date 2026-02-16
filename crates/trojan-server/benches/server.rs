//! Benchmarks for trojan-server components.

use std::net::IpAddr;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use trojan_config::WebSocketConfig;
use trojan_server::RateLimiter;
use trojan_server::ws::inspect_mixed;

fn sample_ws_config() -> WebSocketConfig {
    WebSocketConfig {
        enabled: true,
        mode: "mixed".to_string(),
        path: "/ws".to_string(),
        host: Some("example.com".to_string()),
        listen: None,
        max_frame_bytes: 0,
    }
}

fn sample_ws_upgrade_request() -> Vec<u8> {
    b"GET /ws HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n"
        .to_vec()
}

fn sample_http_request() -> Vec<u8> {
    b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: Mozilla/5.0\r\n\
Accept: text/html\r\n\
\r\n"
        .to_vec()
}

fn sample_trojan_header() -> Vec<u8> {
    // Trojan header starts with a 56-byte hex hash
    let mut buf = vec![b'a'; 56];
    buf.extend_from_slice(b"\r\n\x01");
    buf
}

fn bench_inspect_mixed_ws_upgrade(c: &mut Criterion) {
    let cfg = sample_ws_config();
    let request = sample_ws_upgrade_request();

    c.bench_function("inspect_mixed_ws_upgrade", |b| {
        b.iter(|| {
            let result = inspect_mixed(black_box(&request), black_box(&cfg));
            black_box(result)
        })
    });
}

fn bench_inspect_mixed_http_fallback(c: &mut Criterion) {
    let mut cfg = sample_ws_config();
    cfg.host = None;
    let request = sample_http_request();

    c.bench_function("inspect_mixed_http_fallback", |b| {
        b.iter(|| {
            let result = inspect_mixed(black_box(&request), black_box(&cfg));
            black_box(result)
        })
    });
}

fn bench_inspect_mixed_not_http(c: &mut Criterion) {
    let cfg = sample_ws_config();
    let request = sample_trojan_header();

    c.bench_function("inspect_mixed_not_http", |b| {
        b.iter(|| {
            let result = inspect_mixed(black_box(&request), black_box(&cfg));
            black_box(result)
        })
    });
}

fn bench_inspect_mixed_header_sizes(c: &mut Criterion) {
    let cfg = sample_ws_config();

    let mut group = c.benchmark_group("inspect_mixed_header_size");

    // Small headers (typical WS upgrade)
    let small = sample_ws_upgrade_request();
    group.bench_with_input(
        BenchmarkId::from_parameter(small.len()),
        &small,
        |b, req| b.iter(|| inspect_mixed(black_box(req), black_box(&cfg))),
    );

    // Medium headers (with extra headers)
    let mut medium = sample_ws_upgrade_request();
    for i in 0..10 {
        medium.splice(
            medium.len() - 4..medium.len() - 4,
            format!("X-Custom-Header-{}: some-value-here\r\n", i).bytes(),
        );
    }
    group.bench_with_input(
        BenchmarkId::from_parameter(medium.len()),
        &medium,
        |b, req| b.iter(|| inspect_mixed(black_box(req), black_box(&cfg))),
    );

    // Large headers (many custom headers)
    let mut large = sample_ws_upgrade_request();
    for i in 0..50 {
        large.splice(
            large.len() - 4..large.len() - 4,
            format!(
                "X-Custom-Header-{}: some-value-here-with-more-content\r\n",
                i
            )
            .bytes(),
        );
    }
    group.bench_with_input(
        BenchmarkId::from_parameter(large.len()),
        &large,
        |b, req| b.iter(|| inspect_mixed(black_box(req), black_box(&cfg))),
    );

    group.finish();
}

fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter");

    // Test with different limits
    for limit in [100u32, 1000, 10000] {
        let limiter = RateLimiter::new(limit, 60);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(limit),
            &limiter,
            |b, limiter| {
                b.iter(|| {
                    let allowed = limiter.check_and_increment(black_box(ip));
                    black_box(allowed)
                })
            },
        );
    }

    group.finish();
}

fn bench_rate_limiter_many_ips(c: &mut Criterion) {
    let limiter = RateLimiter::new(10000, 60);

    c.bench_function("rate_limiter_many_ips", |b| {
        let mut counter = 0u8;
        b.iter(|| {
            // Cycle through different IPs
            counter = counter.wrapping_add(1);
            let ip: IpAddr = format!("10.0.0.{}", counter).parse().unwrap();
            let allowed = limiter.check_and_increment(black_box(ip));
            black_box(allowed)
        })
    });
}

criterion_group!(
    benches,
    bench_inspect_mixed_ws_upgrade,
    bench_inspect_mixed_http_fallback,
    bench_inspect_mixed_not_http,
    bench_inspect_mixed_header_sizes,
    bench_rate_limiter,
    bench_rate_limiter_many_ips,
);

criterion_main!(benches);
