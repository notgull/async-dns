# dns-protocol

This crate provides a `no_std` implementation of the DNS protocol.

In order to make it trivial for others to build implementations of the DNS protocol, this crate provides a [sans-I/O] implementation of the protocol. This means that it doesn't provide any I/O functionality, but instead provides a way to parse and serialize DNS messages.

In addition, this crate is not only `no_std`, but also `alloc`-free. This means that it can be used in environments where `alloc` is not available, such as embedded systems. It also has no unsafe code.

However, there is a catch. Since this system does not allocate, the user is responsible for providing a buffer to parse DNS messages into. This means that the user must know the maximum size of a DNS message that they will be parsing. This is a reasonable assumption, since DNS messages are limited to 512 bytes in the common case.

## License

Dual licensed under the MIT and Apache 2.0 licenses.