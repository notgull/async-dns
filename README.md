# Asynchronous DNS in Rust

This workspace contains two crates of note:

- [`async-dns`], which provides an asynchronous DNS resolver based on the [`smol`] runtime.
- [`dns-protocol`], which provides a `no_std` implementation of the DNS protocol.

[`async-dns`]: async-dns
[`dns-protocol`]: dns-protocol
[`smol`]: https://crates.io/crates/smol