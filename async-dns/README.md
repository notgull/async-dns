# async-dns

This crate provides asynchronous DNS lookups.

In asynchronous Rust code, it is necessary to resolve URL names using DNS. In most cases, this is done by calling [`getaddrinfo`] on a blocking threadpool. However, since DNS is a UDP-based protocol, it doesn't make much sense to block on a thread when fully asynchronous options are available.

[`getaddrinfo`]: https://man7.org/linux/man-pages/man3/gai_strerror.3.html

This crate provides a fully asynchronous alternative, based on the following mechanisms:

* On Windows, it uses the [`DnsQueryEx`] function, which allows for non-blocking DNS queries.
* On Unix, it uses a custom implementation of DNS provided by the [`dns-protocol`] crate. [`async-fs`] is used to read files and [`async-io`] is used for the actual UDP packets.

It returns the list of addresses that it found to be associated with the given name.

# License

Dual licensed under the MIT and Apache 2.0 licenses.

[`DnsQueryEx`]: https://docs.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex
[`dns-protocol`]: https://crates.io/crates/dns-protocol
[`async-fs`]: https://crates.io/crates/async-fs
[`async-io`]: https://crates.io/crates/async-io