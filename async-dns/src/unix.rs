//! Implementation of `lookup` for Unix systems.
//!
//! This is largely based on the lookup system used in musl libc. Main differences:
//!
//! - Files are read asynchronously.
//! - We check for AAAA addresses after checking for A addresses.
//! - Instead of manually waiting for sockets to become readable, we use several sockets
//!   spawned on different tasks and polled using an executor.
//! - We use a more structured DNS protocol implementation instead of messy raw byte manipulation.
//! - The `memchr` crate is used to optimize certain operations.

use super::AddressInfo;

use async_executor::Executor;
use async_fs::File;
use async_io::{Async, Timer};

use dns_protocol::{Flags, Message, Question, ResourceRecord, ResourceType};

use futures_lite::{future, io::BufReader, prelude::*};
use memchr::memmem;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

pub(super) async fn lookup(name: &str) -> io::Result<Vec<AddressInfo>> {
    // We may be able to use the /etc/hosts resolver.
    if let Some(addr) = from_hosts(name).await? {
        return Ok(vec![addr]);
    }

    // Open a DNS socket and load the config.
    let resolv = ResolvConf::load().await?;

    // Otherwise, we need to use the manual resolver.
    dns_with_search(name, &resolv).await
}

/// Try parsing the name from the "hosts" file.
async fn from_hosts(name: &str) -> io::Result<Option<AddressInfo>> {
    // Open the hosts file.
    let file = File::open("/etc/hosts").await?;
    let mut file = BufReader::new(file);

    // Create a searcher for the name.
    let searcher = memmem::Finder::new(name.as_bytes());

    // Search for the line in the file.
    let mut buf = String::new();

    loop {
        let n = file.read_line(&mut buf).await?;

        // If we read nothing, we reached the end of the file.
        if n == 0 {
            return Ok(None);
        }

        // Pop the newline from the end, if any.
        if buf.ends_with('\n') {
            buf.pop();
        }

        // If the line has a comment, remove it.
        if let Some(n) = memchr::memchr(b'#', buf.as_bytes()) {
            buf.truncate(n);
        }

        // The "hosts" file may contain our name.
        if let Some(index) = searcher.find(buf.as_bytes()) {
            // Get the IP address at the start.
            let ip_addr = match buf[..index].split_whitespace().next() {
                Some(ip_addr) => ip_addr,
                None => continue,
            };

            // Parse the IP address.
            if let Ok(ip_addr) = ip_addr.parse() {
                return Ok(Some(AddressInfo {
                    ip_address: ip_addr,
                }));
            }
        }

        buf.clear();
    }
}

/// Preform a DNS lookup, considering the search variable.
async fn dns_with_search(mut name: &str, resolv: &ResolvConf) -> io::Result<Vec<AddressInfo>> {
    // See if we should just use global scope.
    let num_dots = memchr::memchr_iter(b'.', name.as_bytes()).count();
    let global_scope = num_dots >= resolv.ndots as usize || name.ends_with('.');

    // Remove the dots from the end of `name`, if needed.
    if name.ends_with('.') {
        name = &name[..name.len() - 1];

        // Raise an error if name still ends with a dot.
        if name.ends_with('.') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "name ends with a dot",
            ));
        }
    }

    if global_scope {
        if let Some(search) = resolv.search.as_ref() {
            // Try the name with the search domains.
            let mut buffer = String::from(name);
            buffer.push('.');
            let name_end = buffer.len();

            // Try the name with the search domains.
            for domain in search.split_whitespace() {
                buffer.truncate(name_end);
                buffer.push_str(domain);

                if let Ok(addrs) = dns_lookup(&buffer, resolv).await {
                    return Ok(addrs);
                }
            }
        }
    }

    // Preform a DNS search on just the name.
    dns_lookup(name, resolv).await
}

/// Preform a manual lookup.
async fn dns_lookup(name: &str, resolv: &ResolvConf) -> io::Result<Vec<AddressInfo>> {
    // Create the DNS query.
    let questions = [
        Question::new(name, ResourceType::A, 1),
        Question::new(name, ResourceType::AAAA, 1),
    ];

    match resolv.name_servers.len() {
        0 => {
            // No nameservers, so we can't do anything.
            Ok(vec![])
        }
        1 => {
            // Just poll the one nameserver.
            let addr = resolv.name_servers[0];
            query_nameserver(questions, addr, resolv).await
        }
        _ => {
            // Use an executor to poll futures in parallel.
            let executor = Executor::new();
            let mut tasks = Vec::with_capacity(resolv.name_servers.len());

            for ns in resolv.name_servers.iter().copied() {
                tasks.push(
                    executor.spawn(async move { query_nameserver(questions, ns, resolv).await }),
                );
            }

            // Poll until every task is complete.
            executor
                .run(async move {
                    let mut info = Vec::with_capacity(tasks.len());
                    for task in tasks {
                        info.append(&mut task.await?);
                    }
                    Ok(info)
                })
                .await
        }
    }
}

/// Poll for a DNS response on the given nameserver.
async fn query_nameserver(
    mut questions: [Question<'_>; 2],
    nameserver: IpAddr,
    resolv: &ResolvConf,
) -> io::Result<Vec<AddressInfo>> {
    const MAX_ANSWERS: usize = 16;

    /// The result of waiting for a packet on a fixed timeout.
    enum WaitResult {
        /// The packet was received.
        Packet { len: usize },
        /// The timeout expired.
        TimedOut,
    }

    let mut addrs = vec![];

    // Create the DNS query.
    let id = fastrand::u16(..);
    let message = Message::new(
        id,
        Flags::standard_query(),
        &mut questions,
        &mut [],
        &mut [],
        &mut [],
    );

    // Serialize it to a buffer.
    let mut stack_buffer = [0; 512];
    let mut heap_buffer = None;
    let needed = message.space_needed();

    // Use the stack if we can, but switch to the heap if it's not enough.
    let buf = if needed > stack_buffer.len() {
        heap_buffer.insert(vec![0; needed]).as_mut_slice()
    } else {
        &mut stack_buffer
    };

    let len = message
        .write(buf)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, ErrWrap(err)))?;

    // Write the query to the nameserver address.
    let socket = Async::<UdpSocket>::bind(([127, 0, 0, 1], 0))?;
    let foreign_addr = SocketAddr::new(nameserver, 53);

    for _ in 0..resolv.attempts {
        socket.send_to(&buf[..len], foreign_addr).await?;

        // Wait for `timeout` seconds for a response.
        let timeout = Timer::after(Duration::from_secs(resolv.timeout.into()));
        let timeout = async move {
            timeout.await;
            io::Result::Ok(WaitResult::TimedOut)
        };

        let result = future::or(
            async {
                let len = socket.recv(buf).await?;
                Ok(WaitResult::Packet { len })
            },
            timeout,
        )
        .await?;

        // Get the length of the packet we're reading.
        let len = match result {
            WaitResult::Packet { len } => len,
            WaitResult::TimedOut => {
                // Try again. Use yield_now() to give other tasks time if we're in an executor.
                future::yield_now().await;
                continue;
            }
        };

        // Parse the packet.
        let mut questions = [Question::default(); 2];
        let mut answers = [ResourceRecord::default(); MAX_ANSWERS];
        let message = Message::read(&buf[..len], &mut questions, &mut answers, &mut [], &mut [])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, ErrWrap(err)))?;

        // Check the ID.
        if message.id() != id {
            // Try again.
            future::yield_now().await;
            continue;
        }

        // If the reply was truncated, return an error.
        // TODO(notgull): If the packet was truncated, try again with TCP.
        if message.flags().truncated() {
            return Err(io::Error::new(io::ErrorKind::Other, "packet was truncated"));
        }

        // Parse the resulting answer.
        addrs.extend(message.answers().iter().filter_map(|answer| {
            let data = answer.data();

            // Parse the data as an IP address.
            match data.len() {
                4 => {
                    let mut bytes = [0; 4];
                    bytes.copy_from_slice(data);
                    Some(AddressInfo {
                        ip_address: IpAddr::V4(bytes.into()),
                    })
                }
                16 => {
                    let mut bytes = [0; 16];
                    bytes.copy_from_slice(data);
                    Some(AddressInfo {
                        ip_address: IpAddr::V6(bytes.into()),
                    })
                }
                _ => None,
            }
        }));

        // We got a response, so we're done.
        break;
    }

    Ok(addrs)
}

/// Structural form of `resolv.conf`.
struct ResolvConf {
    /// The list of name servers.
    name_servers: Vec<IpAddr>,

    /// Maximum number of segments in the domain name.
    ndots: u8,

    /// Maximum timeout in seconds.
    timeout: u8,

    /// Maximum number of retries.
    attempts: u8,

    /// The search domain to use.
    search: Option<String>,
}

impl ResolvConf {
    /// Load the current configuration from /etc/resolv.conf.
    async fn load() -> io::Result<Self> {
        // Open the file.
        let file = File::open("/etc/resolv.conf").await?;
        let mut file = BufReader::new(file);

        // Default configuration values.
        let mut config = ResolvConf {
            name_servers: vec![],
            ndots: 1,
            timeout: 5,
            attempts: 2,
            search: None,
        };

        // Begin reading lines.
        let mut buf = String::new();

        loop {
            // Read a line.
            buf.clear();
            let n = file.read_line(&mut buf).await?;

            // If we read nothing, we reached the end of the file.
            if n == 0 {
                break;
            }

            // Pop the newline from the end, if any.
            if buf.ends_with('\n') {
                buf.pop();
            }

            // If there is a comment, remove it.
            if let Some(n) = memchr::memchr(b'#', buf.as_bytes()) {
                buf.truncate(n);
            }

            if let Some(ns) = buf.strip_prefix("nameserver") {
                // Parse the IP address.
                if let Ok(ip_addr) = ns.trim().parse() {
                    config.name_servers.push(ip_addr);
                }

                continue;
            } else if let Some(options) = buf.strip_prefix("options") {
                // Try to find the options.
                if let Some(ndots_index) = memmem::find(options.as_bytes(), b"ndots:") {
                    // Parse the number of dots.
                    if let Ok(ndots) = options[ndots_index + 6..].trim().parse() {
                        config.ndots = ndots;
                    }

                    continue;
                } else if let Some(timeout_index) = memmem::find(options.as_bytes(), b"timeout:") {
                    // Parse the timeout.
                    if let Ok(timeout) = options[timeout_index + 8..].trim().parse() {
                        config.timeout = timeout;
                    }

                    continue;
                } else if let Some(attempts_index) = memmem::find(options.as_bytes(), b"attempts:")
                {
                    // Parse the number of attempts.
                    if let Ok(attempts) = options[attempts_index + 9..].trim().parse() {
                        config.attempts = attempts;
                    }

                    continue;
                }
            }

            // See if we have a search domain.
            let search = match buf.strip_prefix("search") {
                Some(search) => search,
                None => match buf.strip_prefix("domain") {
                    Some(search) => search,
                    None => continue,
                },
            };

            // Parse the search domain.
            config.search = Some(search.trim().to_string());
        }

        Ok(config)
    }
}

/// Wraps `dns_protocol::Error` so that outside types can't access it, preventing `dns_protocol` from being a public dependency.
struct ErrWrap(dns_protocol::Error);

impl From<dns_protocol::Error> for ErrWrap {
    fn from(err: dns_protocol::Error) -> Self {
        ErrWrap(err)
    }
}

impl fmt::Debug for ErrWrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for ErrWrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for ErrWrap {}
