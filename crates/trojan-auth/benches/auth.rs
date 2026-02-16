//! Benchmarks for trojan authentication.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use trojan_auth::{AuthBackend, MemoryAuth, sha224_hex, verify_password};

fn bench_sha224_hex(c: &mut Criterion) {
    let passwords = [
        "short",
        "medium_password_here",
        "this_is_a_much_longer_password_that_someone_might_actually_use_in_practice",
    ];

    let mut group = c.benchmark_group("sha224_hex");
    for password in passwords {
        group.bench_with_input(
            BenchmarkId::from_parameter(password.len()),
            password,
            |b, p| b.iter(|| sha224_hex(black_box(p))),
        );
    }
    group.finish();
}

fn bench_verify_password(c: &mut Criterion) {
    let password = "test_password_123";
    let hash = sha224_hex(password);

    c.bench_function("verify_password_correct", |b| {
        b.iter(|| verify_password(black_box(password), black_box(&hash)))
    });

    c.bench_function("verify_password_wrong", |b| {
        b.iter(|| verify_password(black_box("wrong_password"), black_box(&hash)))
    });
}

fn bench_memory_auth_verify(c: &mut Criterion) {
    // Small auth backend (10 users)
    let passwords_10: Vec<_> = (0..10).map(|i| format!("password_{i}")).collect();
    let auth_10 = MemoryAuth::from_passwords(&passwords_10);
    let hash_10 = sha224_hex(&passwords_10[5]);

    // Medium auth backend (100 users)
    let passwords_100: Vec<_> = (0..100).map(|i| format!("password_{i}")).collect();
    let auth_100 = MemoryAuth::from_passwords(&passwords_100);
    let hash_100 = sha224_hex(&passwords_100[50]);

    // Large auth backend (1000 users)
    let passwords_1000: Vec<_> = (0..1000).map(|i| format!("password_{i}")).collect();
    let auth_1000 = MemoryAuth::from_passwords(&passwords_1000);
    let hash_1000 = sha224_hex(&passwords_1000[500]);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("memory_auth_verify");

    group.bench_function("10_users", |b| {
        b.iter(|| rt.block_on(auth_10.verify(black_box(&hash_10))))
    });

    group.bench_function("100_users", |b| {
        b.iter(|| rt.block_on(auth_100.verify(black_box(&hash_100))))
    });

    group.bench_function("1000_users", |b| {
        b.iter(|| rt.block_on(auth_1000.verify(black_box(&hash_1000))))
    });

    // Benchmark miss (not found)
    let invalid_hash = sha224_hex("nonexistent_password");
    group.bench_function("1000_users_miss", |b| {
        b.iter(|| rt.block_on(auth_1000.verify(black_box(&invalid_hash))))
    });

    group.finish();
}

fn bench_memory_auth_from_passwords(c: &mut Criterion) {
    let passwords_10: Vec<_> = (0..10).map(|i| format!("password_{i}")).collect();
    let passwords_100: Vec<_> = (0..100).map(|i| format!("password_{i}")).collect();

    let mut group = c.benchmark_group("memory_auth_from_passwords");

    group.bench_function("10_passwords", |b| {
        b.iter(|| MemoryAuth::from_passwords(black_box(&passwords_10)))
    });

    group.bench_function("100_passwords", |b| {
        b.iter(|| MemoryAuth::from_passwords(black_box(&passwords_100)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha224_hex,
    bench_verify_password,
    bench_memory_auth_verify,
    bench_memory_auth_from_passwords,
);

criterion_main!(benches);
