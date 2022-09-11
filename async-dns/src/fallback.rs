//! "The coward's way out": Just do whatever libstd does, but in a threadpool.

use super::AddressInfo;

use std::io;
use std::net::ToSocketAddrs;

pub(super) async fn lookup(name: &str) -> io::Result<Vec<AddressInfo>> {
    let name = name.to_string();

    // Spawn the lookup on a threadpool.
    Ok(blocking::unblock(move || {
        let mut addrs = Vec::new();
        for addr in name.to_socket_addrs()? {
            addrs.push(AddressInfo {
                ip_address: addr.ip(),
            });
        }
        Ok(addrs)
    }))
}
