//! lookup.rs example adapted into a test.
//!
//! Will work as long as google.com exists.

#[test]
fn google_lookup() {
    async_io::block_on(async {
        // Perform the lookup.
        let ips = async_dns::lookup("google.com").await.unwrap();
        assert_ne!(ips.count(), 0);
    });
}
