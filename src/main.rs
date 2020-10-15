use std::io::{self, BufRead};
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::vec::Vec;

// exnc:
// echo - xxd - netcat
// --ascii: expect input in newline-terminated hexadecimal strings, 0-9a-fA-F
// --binary: direct binary stream as expected (until eof) to network port

fn send_data<SocketType>(socket: UdpSocket, data: Vec::<u8>, destination_address: SocketAddr) -> std::io::Result<()> {
    {
        socket.send_to(&data, &destination_address);
    }
    Ok(()) // what does this do?
}

enum OperatingMode {
    InputIsHex,
    InputIsBinary
}

fn line_to_buffer(mode: OperatingMode, /*mut result: &Vec::<u8>,*/ line: String) 
    -> std::result::Result<Vec::<u8>, &'static str> {
    match mode {
        OperatingMode::InputIsHex => {
            let result = Vec::<u8>::new();
            Ok(result)
        },
            //result = &Vec::<u8>::from(line.as_bytes());
            let result = Vec::<u8>::from(line);
            Ok(result)
        },
        _ => Err("shits fucked man")
    }
}

fn main() {
    println!("Hello, world!");

    println!("{:?}", line_to_buffer(OperatingMode::InputIsBinary, "test buffer".to_string()).unwrap());
}
