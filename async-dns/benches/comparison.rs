//! Comparison of `async-dns` with a regular blocking lookup.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn async_dns_lookup(b: &mut Criterion) {
    b.bench_function("async-dns", |b| {
        b.iter(|| {
            async_io::block_on(async {
                // Perform the lookup.
                let ips = async_dns::lookup("google.com").await.unwrap();
                black_box(ips.collect::<Vec<_>>());
            });
        });
    });
}

fn blocking_lookup(b: &mut Criterion) {
    b.bench_function("blocking", |b| {
        b.iter(|| {
            async_io::block_on(async {
                let ips = blocking::unblock(|| {
                    std::net::ToSocketAddrs::to_socket_addrs("google.com:53")
                        .unwrap()
                        .collect::<Vec<_>>()
                })
                .await;
                black_box(ips);
            });
        });
    });
}

criterion_group! {
    benches,
    async_dns_lookup,
    blocking_lookup,
}

criterion_main!(benches);
