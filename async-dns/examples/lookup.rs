//! Preform an asynchronous namespace lookup.

use std::env;
use std::process;

fn main() {
    async_io::block_on(async {
        // Get the arguments/name to lookup.
        let mut args = env::args();
        let program_name = args.next().unwrap();

        let name = match args.next() {
            Some(name) => name,
            None => {
                eprintln!("Usage: {} <name>", program_name);
                process::exit(1);
            }
        };

        // Perform the lookup.
        let ips = async_dns::lookup(&name).await.unwrap();

        // Print the results.
        println!("{}:", name);
        for ip in ips {
            println!(" - {}", &ip.ip_address);
        }
    });
}
