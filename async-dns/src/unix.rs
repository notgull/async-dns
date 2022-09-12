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

use std::cmp;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub(super) async fn lookup(name: &str) -> io::Result<Vec<AddressInfo>> {
    // We may be able to use the /etc/hosts resolver.
    if let Some(addr) = from_hosts(name).await? {
        return Ok(vec![addr]);
    }

    // Otherwise, we need to use the manual resolver.
    let resolv = ResolvConf::load().await?;
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
                    if !addrs.is_empty() {
                        return Ok(addrs);
                    }
                }
            }
        }
    }

    // Preform a DNS search on just the name.
    dns_lookup(name, resolv).await
}

/// Preform a manual lookup for the name.
async fn dns_lookup(name: &str, resolv: &ResolvConf) -> io::Result<Vec<AddressInfo>> {
    match resolv.name_servers.len() {
        0 => {
            // No nameservers, so we can't do anything.
            Ok(vec![])
        }
        1 => {
            // Just poll the one nameserver.
            let addr = resolv.name_servers[0];
            query_name_and_nameserver(name, addr, resolv).await
        }
        _ => {
            // Use an executor to poll futures in parallel.
            let executor = Executor::new();
            let mut tasks = Vec::with_capacity(resolv.name_servers.len());

            for ns in resolv.name_servers.iter().copied() {
                tasks.push(
                    executor
                        .spawn(async move { query_name_and_nameserver(name, ns, resolv).await }),
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

/// Poll for the name on the given nameserver.
async fn query_name_and_nameserver(
    name: &str,
    nameserver: IpAddr,
    resolv: &ResolvConf,
) -> io::Result<Vec<AddressInfo>> {
    // Try to poll for an IPv4 address first.
    let mut addrs =
        query_question_and_nameserver(Question::new(name, ResourceType::A, 1), nameserver, resolv)
            .await?;

    // If we didn't get any addresses, try an IPv6 address.
    if addrs.is_empty() {
        addrs = query_question_and_nameserver(
            Question::new(name, ResourceType::AAAA, 1),
            nameserver,
            resolv,
        )
        .await?;
    }

    Ok(addrs)
}

/// Poll for a DNS response on the given nameserver.
async fn query_question_and_nameserver(
    question: Question<'_>,
    nameserver: IpAddr,
    resolv: &ResolvConf,
) -> io::Result<Vec<AddressInfo>> {
    // Create the DNS query.
    // I'd like to use two questions at once, but at least the DNS system I use just drops the packet.
    let id = fastrand::u16(..);
    let mut questions = [question];
    let message = Message::new(
        id,
        Flags::standard_query(),
        &mut questions,
        &mut [],
        &mut [],
        &mut [],
    );

    // Serialize it to a buffer.
    let mut stack_buffer = [0; 1024];
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

    // The query may be too large, so we need to use TCP.
    if len <= 512 {
        if let Some(addrs) = question_with_udp(id, &buf[..len], nameserver, resolv).await? {
            return Ok(addrs);
        }
    }

    // We were unable to complete the query over UDP, use TCP instead.
    question_with_tcp(id, &buf[..len], nameserver).await
}

/// Query a nameserver for the given question, using the UDP protocol.
///
/// Returns `None` if the UDP query failed and TCP should be used instead.
async fn question_with_udp(
    id: u16,
    query: &[u8],
    nameserver: IpAddr,
    resolv: &ResolvConf,
) -> io::Result<Option<Vec<AddressInfo>>> {
    const RECORD_BUFSIZE: usize = 16;

    /// The result of waiting for a packet on a fixed timeout.
    enum WaitResult {
        /// The packet was received.
        Packet { len: usize },
        /// The timeout expired.
        TimedOut,
    }

    let mut addrs = vec![];

    // Write the query to the nameserver address.
    let socket = Async::<UdpSocket>::bind(([127, 0, 0, 1], 0))?;
    let foreign_addr = SocketAddr::new(nameserver, 53);

    // UDP queries are limited to 512 bytes.
    let mut buf = [0; 512];

    for _ in 0..resolv.attempts {
        socket.send_to(query, foreign_addr).await?;

        // Wait for `timeout` seconds for a response.
        let timeout = Timer::after(Duration::from_secs(resolv.timeout.into()));
        let timeout = async move {
            timeout.await;
            io::Result::Ok(WaitResult::TimedOut)
        };
        let read_packet = async {
            let len = socket.recv(&mut buf).await?;
            io::Result::Ok(WaitResult::Packet { len })
        };

        let result = future::or(read_packet, timeout).await?;

        // Get the length of the packet we're reading.
        let len = match result {
            WaitResult::Packet { len } => len,
            WaitResult::TimedOut => {
                // Try again. Use yield_now() to give other tasks time if we're in an executor.
                future::yield_now().await;
                continue;
            }
        };

        // Buffers for DNS results.
        let mut q_buf = [Question::default(); 1];
        let mut answers = [ResourceRecord::default(); RECORD_BUFSIZE];
        let mut authority = [ResourceRecord::default(); RECORD_BUFSIZE];
        let mut additional = [ResourceRecord::default(); RECORD_BUFSIZE];

        // Parse the packet.
        let message = Message::read(
            &buf[..len],
            &mut q_buf,
            &mut answers,
            &mut authority,
            &mut additional,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, ErrWrap(err)))?;

        // Check the ID.
        if message.id() != id {
            // Try again.
            future::yield_now().await;
            continue;
        }

        // If the reply was truncated, it's too large for UDP.
        if message.flags().truncated() {
            return Ok(None);
        }

        // Parse the resulting answer.
        parse_answers(&message, &mut addrs);

        // We got a response, so we're done.
        return Ok(Some(addrs));
    }

    // We did not receive a response.
    Ok(None)
}

/// Query a nameserver for the given question, using the TCP protocol.
#[cold]
async fn question_with_tcp(
    id: u16,
    query: &[u8],
    nameserver: IpAddr,
) -> io::Result<Vec<AddressInfo>> {
    const RECORD_BUFSIZE: usize = 16;

    if query.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "query too large for TCP",
        ));
    }

    // Open the socket to the server.
    let mut socket = Async::<TcpStream>::connect((nameserver, 53)).await?;

    // Write the length of the query.
    let len_bytes = (query.len() as u16).to_be_bytes();
    socket.write_all(&len_bytes).await?;

    // Write the query.
    socket.write_all(query).await?;

    // Read the length of the response.
    let mut len_bytes = [0; 2];
    socket.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    // Read the response.
    let mut stack_buffer = [0; 1024];
    let mut heap_buffer = None;
    let buf = if len > stack_buffer.len() {
        heap_buffer.insert(vec![0; len]).as_mut_slice()
    } else {
        &mut stack_buffer
    };

    socket.read_exact(buf).await?;

    // Parse the response.
    let mut q_buf = [Question::default(); 1];
    let mut answers = [ResourceRecord::default(); RECORD_BUFSIZE];
    let mut authority = [ResourceRecord::default(); RECORD_BUFSIZE];
    let mut additional = [ResourceRecord::default(); RECORD_BUFSIZE];

    let message = Message::read(
        &buf[..len],
        &mut q_buf,
        &mut answers,
        &mut authority,
        &mut additional,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, ErrWrap(err)))?;

    if message.id() != id {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid ID in response",
        ));
    }

    // Parse the answers as address info.
    let mut addrs = vec![];
    parse_answers(&message, &mut addrs);
    Ok(addrs)
}

/// Append address information to the vector, given the DNS response.
fn parse_answers(response: &Message<'_, '_>, addrs: &mut Vec<AddressInfo>) {
    addrs.extend(response.answers().iter().filter_map(|answer| {
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
                if buf.is_empty() {
                    continue;
                }
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
                        config.ndots = cmp::min(ndots, 15);
                    }

                    continue;
                } else if let Some(timeout_index) = memmem::find(options.as_bytes(), b"timeout:") {
                    // Parse the timeout.
                    if let Ok(timeout) = options[timeout_index + 8..].trim().parse() {
                        config.timeout = cmp::min(timeout, 60);
                    }

                    continue;
                } else if let Some(attempts_index) = memmem::find(options.as_bytes(), b"attempts:")
                {
                    // Parse the number of attempts.
                    if let Ok(attempts) = options[attempts_index + 9..].trim().parse() {
                        config.attempts = cmp::min(attempts, 10);
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
