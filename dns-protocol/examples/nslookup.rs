//! Synchronous implementation of `nslookup`, using `dns-protocol`.
//!
//! Only works on Unix.

use std::env;
use std::fs;
use std::io::{prelude::*, BufReader};
use std::net::Ipv4Addr;
use std::net::{IpAddr, UdpSocket};
use std::process;

use dns_protocol::Flags;
use dns_protocol::{Message, Question, ResourceRecord, ResourceType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The first argument is the name to lookup.
    let mut args = env::args();
    let program_name = args.next().unwrap();
    let name = match args.next() {
        Some(name) => name,
        None => {
            eprintln!("Usage: {} <name>", &program_name);
            process::exit(1);
        }
    };

    // Search in resolv.conf for the nameserver.
    //
    // A production-grade implementation would consider multiple nameservers in
    // resolv.conf, and then poll them all at once.
    let resolv = BufReader::new(fs::File::open("/etc/resolv.conf")?);
    let mut nameserver = None;

    for line in resolv.lines() {
        let line = line?;
        if line.starts_with("nameserver") {
            let result = line.split_whitespace().nth(1).unwrap();
            if let Ok(ns) = result.parse::<IpAddr>() {
                nameserver = Some(ns);
                break;
            }
        }
    }

    let nameserver = match nameserver {
        Some(ns) => ns,
        None => {
            eprintln!("No nameserver found in /etc/resolv.conf");
            process::exit(1);
        }
    };

    println!("Nameserver: {}", nameserver);

    // Create the message we need to send.
    let mut questions = [Question::new(name.as_str(), ResourceType::A, 1)];
    let message = Message::new(
        0xFEE7,
        Flags::standard_query(),
        &mut questions,
        &mut [],
        &mut [],
        &mut [],
    );

    // Allocate the buffer that we need to send.
    let mut buffer = vec![0; message.space_needed()];
    message.write(&mut buffer)?;

    // Send the packet to our nameserver over UDP.
    let socket = UdpSocket::bind((Ipv4Addr::from([127, 0, 0, 1]), 0))?;
    socket.send_to(&buffer, (nameserver, 53))?;

    // Wait for a response.
    //
    // A production-grade implementation would respect timeout/attempts settings in
    // resolv.conf.
    let mut buffer = vec![0; 1024];
    let len = socket.recv(&mut buffer)?;

    // Parse the response.
    let mut answers = [ResourceRecord::default(); 16];
    let mut authority = [ResourceRecord::default(); 16];
    let mut additional = [ResourceRecord::default(); 16];
    let message = Message::read(
        &buffer[..len],
        &mut questions,
        &mut answers,
        &mut authority,
        &mut additional,
    )?;

    println!(";; Got answer: {:?}", message.flags().response_code());

    // Print the answers.
    for answer in message.answers() {
        // Determine the IP address.
        match answer.data().len() {
            4 => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(answer.data());
                let ip = Ipv4Addr::from(ip);
                println!("{} has address {}", answer.name(), ip);
            }
            16 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(answer.data());
                let ip = IpAddr::from(ip);
                println!("{} has address {}", answer.name(), ip);
            }
            _ => {
                println!("{} has unknown address type", answer.name());
            }
        }
    }

    Ok(())
}
