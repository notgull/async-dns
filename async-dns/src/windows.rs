//! Windows strategy, using the DNS API.

use super::AddressInfo;
use windows_sys::Win32::Foundation as found;
use windows_sys::Win32::NetworkManagement::Dns as dns;

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::process::abort;

pub(super) async fn lookup(name: &str) -> io::Result<Vec<AddressInfo>> {
    // Query IPv4 addresses.
    let mut addrs = dns_query(name, dns::DNS_TYPE_A).await?;

    // If there are no IPv4 addreses, query IPv6 addresses.
    if addrs.is_empty() {
        addrs = dns_query(name, dns::DNS_TYPE_AAAA).await?;
    }

    Ok(addrs)
}

/// Preform a DNS query for the given DNS type.
async fn dns_query(name: &str, query_type: u16) -> io::Result<Vec<AddressInfo>> {
    // If this future is dropped, we need to cancel the query.
    struct CancelDns(Option<dns::DNS_QUERY_CANCEL>);

    impl CancelDns {
        fn defuse(&mut self) {
            self.0 = None;
        }
    }

    impl Drop for CancelDns {
        fn drop(&mut self) {
            if let Some(cancel) = self.0.take() {
                unsafe {
                    dns::DnsCancelQuery(&cancel);
                }
            }
        }
    }

    // Create a channel to receive the results.
    let (send, recv) = async_channel::bounded(1);

    // Make the actual DNS query.
    let handle = make_query(name, query_type, move |result| {
        // Parse the results.
        let result = unsafe { &mut *result };
        let mut current = result.pQueryRecords;

        if !current.is_null() {
            let mut addrs = Vec::new();

            loop {
                // Parse the current record.
                let record = unsafe { &mut *current };

                match record.wType {
                    dns::DNS_TYPE_A => {
                        // It's an IPv4 Address
                        let ip_addr = unsafe { record.Data.A.IpAddress };

                        let addr_info = AddressInfo {
                            ip_address: IpAddr::V4(ip_addr.to_be_bytes().into()),
                        };

                        addrs.push(addr_info);
                    }
                    dns::DNS_TYPE_AAAA => {
                        // It's an IPv6 Address
                        let ip_addr = unsafe { record.Data.AAAA.Ip6Address.IP6Qword };

                        let left = ip_addr[0].to_be_bytes();
                        let right = ip_addr[1].to_be_bytes();

                        let ip_addr = Ipv6Addr::new(
                            u16::from_be_bytes([left[0], left[1]]),
                            u16::from_be_bytes([left[2], left[3]]),
                            u16::from_be_bytes([left[4], left[5]]),
                            u16::from_be_bytes([left[6], left[7]]),
                            u16::from_be_bytes([right[0], right[1]]),
                            u16::from_be_bytes([right[2], right[3]]),
                            u16::from_be_bytes([right[4], right[5]]),
                            u16::from_be_bytes([right[6], right[7]]),
                        );

                        let addr_info = AddressInfo {
                            ip_address: IpAddr::V6(ip_addr),
                        };

                        addrs.push(addr_info);
                    }
                    _ => {
                        // Not our concern, ignore it.
                    }
                }

                // Move to the next record.
                if record.pNext.is_null() {
                    break;
                } else {
                    current = record.pNext;
                }
            }

            // Free the results.
            unsafe {
                dns::DnsFree(result.pQueryRecords as *const _, dns::DnsFreeRecordList);
            }

            // Send the results.
            let _ = send.try_send(Ok(addrs));
        } else {
            // No available records.
            let _ = send.try_send(Ok(vec![]));
        }
    })?;
    let mut guard = CancelDns(handle);

    // Wait for the request to complete.
    let res = recv
        .recv()
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "channel closed unexpectedly"))?;

    // Now that the future has ended, don't cancel the query.
    guard.defuse();

    res
}

/// Actually make the DNS call, using the given function as a callback.
fn make_query<F>(
    name: &str,
    query_type: u16,
    complete: F,
) -> io::Result<Option<dns::DNS_QUERY_CANCEL>>
where
    F: FnOnce(*mut dns::DNS_QUERY_RESULT),
{
    // Win32 callback function for the completion.
    unsafe extern "system" fn dns_completion_callback<F>(
        closure: *const c_void,
        results: *mut dns::DNS_QUERY_RESULT,
    ) where
        F: FnOnce(*mut dns::DNS_QUERY_RESULT),
    {
        // "closure" is a `Box<F>` in reality.
        let _guard = NoPanic;
        let closure = Box::from_raw(closure as *mut F);
        (closure)(results);
        mem::forget(_guard);
    }

    // Box `complete` and store it on the heap.
    let complete = Box::new(complete);

    // Convert "name" to a wide string.
    let mut name = name.encode_utf16().collect::<Vec<_>>();
    name.push(0);

    // Create the initial request.
    let request = dns::DNS_QUERY_REQUEST {
        Version: dns::DNS_QUERY_REQUEST_VERSION1,
        QueryName: name.as_ptr(),
        QueryType: query_type,
        QueryOptions: 0,
        pDnsServerList: std::ptr::null_mut(),
        pQueryCompletionCallback: Some(dns_completion_callback::<F>),
        pQueryContext: Box::into_raw(complete) as *mut c_void,
        InterfaceIndex: 0,
    };

    // Create space for the results.
    let mut immediate_results = mem::MaybeUninit::<dns::DNS_QUERY_RESULT>::uninit();
    let mut cancel_handle = mem::MaybeUninit::<dns::DNS_QUERY_CANCEL>::uninit();

    // Call the function proper.
    let res = unsafe {
        dns::DnsQueryEx(
            &request,
            immediate_results.as_mut_ptr(),
            cancel_handle.as_mut_ptr(),
        )
    };

    const ERROR_SUCCESS: i32 = found::ERROR_SUCCESS as i32;

    // Determine what the result is.
    match res {
        ERROR_SUCCESS => {
            // The query was successful and it completed immediately.
            // Get the closure back and run it.
            let closure = unsafe { Box::from_raw(request.pQueryContext as *mut F) };
            (closure)(immediate_results.as_mut_ptr());
            Ok(None)
        }
        found::DNS_REQUEST_PENDING => {
            // The request is pending. We should now wait for it.
            Ok(Some(unsafe { cancel_handle.assume_init() }))
        }
        err => {
            // The request failed. The closure will not be called, so dealloc it.
            drop(unsafe { Box::from_raw(request.pQueryContext as *mut F) });

            // This may be a DNS error.
            if matches!(err, 0x2329..=0x26B2) {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("DNS error: {}", err - 0x2328),
                ))
            } else {
                // Otherwise, it's a Win32 error.
                Err(io::Error::from_raw_os_error(err))
            }
        }
    }
}

/// If a panic occurs, abort the process.
struct NoPanic;

impl Drop for NoPanic {
    fn drop(&mut self) {
        abort();
    }
}
