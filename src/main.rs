use std::io::{self, BufRead};
use std::net::UdpSocket;
use std::net::SocketAddr;
use std::vec::Vec;
use std::iter::Iterator;
use std::result::Result;

use argparse::{ArgumentParser, StoreTrue, Store};
use faster_hex::hex_decode;

// exnc:
// echo - xxd - netcat
// --ascii: expect input in newline-terminated hexadecimal strings, 0-9a-fA-F
// --binary: direct binary stream as expected (until eof) to network port

// if it fails should we bail? I think so because this is a core functionality
fn send_data(socket: &UdpSocket, data: &[u8], destination_address: &SocketAddr) -> std::io::Result<()> {
    let result = socket.send_to(&data, &destination_address);

    match result {
        Ok(bytes) => Ok(()),
        Err(error) => panic!("Unable to send data to {:?} because {:?}", destination_address, error),
    }
}

#[derive(Debug)]
enum OperatingMode {
    InputIsHex,
    InputIsBinary
}

#[derive(Debug,PartialEq)]
enum ExncError {
    HexDecodeError,
    UnrecognizedModeError,
}

fn line_to_buffer(mode: &OperatingMode, line: &[u8], buffer: &mut Vec<u8>) 
    -> Result<Vec<u8>, ExncError> {
    match mode {
        OperatingMode::InputIsHex => {
            // buffer needs to be exactly half the size of the line, use rshift for speed + correctness
            buffer.resize(line.len() >> 1, 0);
            match hex_decode(line, buffer) {
                Ok(_result) => {
                    Ok(buffer.to_vec()) // TODO: just use Ok(())
                },
                Err(_error) => {
                    Err(ExncError::HexDecodeError)
                }
            } 
        },
        OperatingMode::InputIsBinary => {
            //result = &Vec::<u8>::from(line.as_bytes());
            //let result = Vec::<u8>::from(line);
            //*buffer = Vec::<u8>::from(line);
            *buffer = line.into();
            Ok(buffer.to_vec())//result)
        },
        _ => Err(ExncError::UnrecognizedModeError)
    }
}

#[derive(Debug)]
struct ExncOptions {
    mode: OperatingMode,
    dest: SocketAddr,
    sock: UdpSocket
}

fn setup_mode(ascii_hex: bool, binary: bool) -> OperatingMode {
    // Check that the options are valid
    if ascii_hex && binary {
        // we can only have one of these
        panic!("Cannot be in ASCII hex mode and binary mode at the same time");
    }

    /* Checking only ascii_hex here has the effect of making --binary the default
     * even when nothing was specified on the command line.
     */
    if ascii_hex {
        OperatingMode::InputIsHex
    } else {
        OperatingMode::InputIsBinary
    }
}

fn setup_dest_address(dest: &str) -> SocketAddr {
    // Check the destination address
    // Need the type annotation for it to know how to parse()
    dest.parse().expect("invalid destination address specified, make sure it follows host_ip:port syntax")
}

fn setup_source_socket(port: &str) -> UdpSocket {
    let port: u16 = port.parse().expect("invalid port specified, must be an unsigned 16-bit integer (0-65535)");
    let addrs = [
        SocketAddr::from(([127,0,0,1], port)),
    ];
    UdpSocket::bind(&addrs[..]).expect("unable to bind to UDP socket for sending data")
}

fn get_cli_options() -> ExncOptions {
    /* Defaults listed here; booleans must be false! */
    let mut ascii_hex = false;
    let mut binary = false;
    let mut dest = "127.0.0.1:6868".to_string();
    let mut port = "45354".to_string();
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Echo binary data to a UDP socket");
        parser.refer(&mut ascii_hex)
            .add_option(&["-a", "--hex"], StoreTrue,
                        "Interpret input data as ASCII formatted hexadecimal bytes, where each newline creates a new message");
        parser.refer(&mut binary)
            .add_option(&["-b", "--binary"], StoreTrue,
                        "Interpret input data as raw binary, forwarded directly to the destination");
        parser.refer(&mut dest)
            .add_option(&["-d", "--destination"], Store,
                        "Destination address for the UDP data (formatted host_ip:port_number)");
        parser.refer(&mut port)
            .add_option(&["-p", "--port"], Store,
                        "Port from which we send the data (this program binds this port)");
        parser.parse_args_or_exit();
    }

    let mode = setup_mode(ascii_hex, binary);

    let destination = setup_dest_address(&dest);

    let sock = setup_source_socket(&port);

    let options = ExncOptions {
        mode,
        dest: destination,
        sock
    };

    println!("Configured options: {:?}", options);
    options
}
// TODO: abstract out to BufRead! so we can use this same code for files >:)
fn process_stdin(options: &ExncOptions) {
    let stdin = io::stdin();
    match options.mode {
        OperatingMode::InputIsHex => {
            process_lines(options, stdin.lock().lines());
        },
        OperatingMode::InputIsBinary => {
            let mut contents = Vec::new();
            let mut buffer = Vec::new();
            stdin.lock().read_to_end(&mut contents);
            process_line(options, &contents, &mut buffer); 

        }
    }
}

fn process_line(options: &ExncOptions, line: &[u8], buffer: &mut Vec<u8>) -> Result<Vec<u8>, ExncError> {
    line_to_buffer(&options.mode, line, buffer)?;
    send_data(&options.sock, &buffer, &options.dest);
    buffer.clear();
    Ok(buffer.to_vec())
}

fn process_lines<T: Iterator<Item = std::io::Result<String>>>(options: &ExncOptions, lines: T) {
    //let stdin = io::stdin();
    let mut buffer = Vec::new();//Vec::<u8>::with_capacity(65535); /* TODO: max this a named constant, max udp packet size */
    for line in lines { // TODO: abstract this to any line iterable
        match process_line(options, line.unwrap().as_bytes(), &mut buffer) {
            Ok(_) => {
            },
            Err(error) => {
                println!("[ERROR] {:?}", error);
                continue;
            }
        }
    }
}

fn main() {

    let options = get_cli_options();

    let mut buffer = Vec::with_capacity(1024);//vec![0; 1024];

    let data = line_to_buffer(&OperatingMode::InputIsBinary, b"test_buffer", &mut buffer).unwrap();
    println!("{:?}", data);

    let mut asciibuffer = Vec::with_capacity(1024);//vec![0; 1024];
    let ascii = line_to_buffer(&OperatingMode::InputIsHex, b"should fail", &mut asciibuffer);
    assert_eq!(ascii, Err(ExncError::HexDecodeError));

    let ascii = line_to_buffer(&OperatingMode::InputIsHex, b"ff00ffe", &mut asciibuffer);
    assert_eq!(ascii, Err(ExncError::HexDecodeError));

    process_stdin(&options);

    send_data(&options.sock, &data, &options.dest);

}
