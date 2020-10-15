use std::io::{self, BufRead};
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::vec::Vec;

// exnc:
// echo - xxd - netcat
// --ascii: expect input in newline-terminated hexadecimal strings, 0-9a-fA-F
// --binary: direct binary stream as expected (until eof) to network port

fn send_data(socket: UdpSocket, data: Vec::<u8>, destination_address: SocketAddr) -> std::io::Result<()> {
    let result = socket.send_to(&data, &destination_address);

    let result = match result {
        Ok(bytes) => Ok(()),
        Err(error) => panic!("Unable to send data to {:?} because {:?}", destination_address, error),
    };
    result
}

enum OperatingMode {
    InputIsHex,
    InputIsBinary
}

fn line_to_buffer(mode: OperatingMode, line: String) 
    -> std::result::Result<Vec::<u8>, &'static str> {
    match mode {
        OperatingMode::InputIsHex => {
            let result = Vec::<u8>::new();
            Ok(result)
        },
        OperatingMode::InputIsBinary => {
            //result = &Vec::<u8>::from(line.as_bytes());
            let result = Vec::<u8>::from(line);
            Ok(result)
        },
        _ => Err("Unrecognized mode")
    }
}

fn main() {
    let data = line_to_buffer(OperatingMode::InputIsBinary, "test_buffer".to_string()).unwrap();
    println!("{:?}", data);

    let dest: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:45354").expect("unable to bind to UDP socket for sending data");

    send_data(socket, data, dest);

}
