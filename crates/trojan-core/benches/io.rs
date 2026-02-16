//! Benchmarks for trojan-core I/O utilities.

use std::time::Duration;

use bytes::Bytes;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use trojan_core::io::{NoOpMetrics, PrefixedStream, relay_bidirectional};

fn bench_prefixed_stream_read(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("prefixed_stream_read");

    for prefix_size in [64, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(prefix_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(prefix_size),
            &prefix_size,
            |b, &size| {
                b.iter(|| {
                    rt.block_on(async {
                        let prefix = Bytes::from(vec![b'x'; size]);
                        let (_client, server) = duplex(1024);
                        let mut prefixed = PrefixedStream::new(prefix, server);

                        let mut buf = vec![0u8; size + 64];
                        let n = prefixed.read(&mut buf).await.unwrap();
                        black_box(n);
                    })
                })
            },
        );
    }

    group.finish();
}

fn bench_prefixed_stream_partial_read(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("prefixed_stream_partial_read", |b| {
        b.iter(|| {
            rt.block_on(async {
                let prefix = Bytes::from(vec![b'x'; 1024]);
                let (_client, server) = duplex(1024);
                let mut prefixed = PrefixedStream::new(prefix, server);

                let mut buf = [0u8; 64];
                // Read prefix in small chunks
                for _ in 0..16 {
                    let n = prefixed.read(&mut buf).await.unwrap();
                    black_box(n);
                }
            })
        })
    });
}

fn bench_relay_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("relay_throughput");

    // Test different data sizes
    for data_size in [1024, 8192, 65536] {
        group.throughput(Throughput::Bytes(data_size as u64 * 2)); // bidirectional
        group.bench_with_input(
            BenchmarkId::from_parameter(data_size),
            &data_size,
            |b, &size| {
                let data = vec![b'x'; size];
                b.iter(|| {
                    rt.block_on(async {
                        let (client, server_side) = duplex(size * 2);
                        let (target_side, target) = duplex(size * 2);

                        let data_clone = data.clone();
                        let relay_handle = tokio::spawn(async move {
                            relay_bidirectional(
                                server_side,
                                target_side,
                                Duration::from_secs(5),
                                8192,
                                &NoOpMetrics,
                            )
                            .await
                        });

                        let (mut client_r, mut client_w) = tokio::io::split(client);
                        let (mut target_r, mut target_w) = tokio::io::split(target);

                        // Client -> Target
                        let send_handle = tokio::spawn(async move {
                            client_w.write_all(&data_clone).await.unwrap();
                            client_w.shutdown().await.unwrap();
                        });

                        // Target reads and responds
                        let mut buf = vec![0u8; size];
                        target_r.read_exact(&mut buf).await.unwrap();

                        target_w.write_all(&buf).await.unwrap();
                        target_w.shutdown().await.unwrap();

                        // Client reads response
                        client_r.read_exact(&mut buf).await.unwrap();

                        send_handle.await.unwrap();
                        relay_handle.await.unwrap().unwrap();

                        black_box(buf);
                    })
                })
            },
        );
    }

    group.finish();
}

fn bench_relay_buffer_sizes(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("relay_buffer_size");

    let data_size = 32768;

    // Test different buffer sizes
    for buffer_size in [1024, 4096, 8192, 16384] {
        group.bench_with_input(
            BenchmarkId::from_parameter(buffer_size),
            &buffer_size,
            |b, &buf_size| {
                let data = vec![b'x'; data_size];
                b.iter(|| {
                    rt.block_on(async {
                        let (client, server_side) = duplex(data_size * 2);
                        let (target_side, target) = duplex(data_size * 2);

                        let data_clone = data.clone();
                        let relay_handle = tokio::spawn(async move {
                            relay_bidirectional(
                                server_side,
                                target_side,
                                Duration::from_secs(5),
                                buf_size,
                                &NoOpMetrics,
                            )
                            .await
                        });

                        let (mut client_r, mut client_w) = tokio::io::split(client);
                        let (mut target_r, mut target_w) = tokio::io::split(target);

                        let send_handle = tokio::spawn(async move {
                            client_w.write_all(&data_clone).await.unwrap();
                            client_w.shutdown().await.unwrap();
                        });

                        let mut buf = vec![0u8; data_size];
                        target_r.read_exact(&mut buf).await.unwrap();

                        target_w.write_all(&buf).await.unwrap();
                        target_w.shutdown().await.unwrap();

                        client_r.read_exact(&mut buf).await.unwrap();

                        send_handle.await.unwrap();
                        relay_handle.await.unwrap().unwrap();

                        black_box(buf);
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_prefixed_stream_read,
    bench_prefixed_stream_partial_read,
    bench_relay_throughput,
    bench_relay_buffer_sizes,
);

criterion_main!(benches);
