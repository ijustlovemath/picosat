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
fn send_data(socket: &UdpSocket, data: &[u8], destination_address: &SocketAddr) {
    let result = socket.send_to(&data, &destination_address);

    match result {
        Ok(_bytes_sent) => {},
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
    -> Result<(), ExncError> {
    match mode {
        OperatingMode::InputIsHex => {
            // buffer needs to be exactly half the size of the line, use rshift for speed + correctness
            buffer.resize(line.len() >> 1, 0);
            match hex_decode(line, buffer) {
                Ok(_result) => {
                    Ok(()) 
                },
                Err(_error) => {
                    Err(ExncError::HexDecodeError)
                }
            } 
        },
        OperatingMode::InputIsBinary => {
            *buffer = line.into();
            Ok(())
        },
        _ => Err(ExncError::UnrecognizedModeError)
    }
}

#[derive(Debug)]
struct ExncOptions {
    mode: OperatingMode,
    dest: SocketAddr,
    sock: UdpSocket,
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

fn drain_into<T: BufRead>(mut source: T, sink: &mut Vec<u8>) {
    loop {
        match source.read_until(0, sink) {
            Ok(bytes_read) => {
                if bytes_read > 0 {
                    continue;
                } else {
                    break;
                }
            },
            Err(error) => {
                println!("[ERROR] drain failed: {:?}", error);
                break;
            }
        }
    }
}

fn process_stdin(options: &ExncOptions) {
    let stdin = io::stdin();
    process_file(options, stdin.lock());
}

fn process_file<T: BufRead>(options: &ExncOptions, source: T) {
    match options.mode {
        OperatingMode::InputIsHex => {
            process_lines(options, source.lines());
        },
        OperatingMode::InputIsBinary => {
            let mut contents = Vec::new();
            let mut buffer = Vec::new();
            drain_into(source, &mut contents);
            match process_line(options, &contents, &mut buffer) {
                Ok(_) => {},
                Err(_impossible) => {
                    // This shouldn't happen because when you're operating in binary mode, the only thing we do that
                    // can fail is draining the source file, but those errors are handled within the drain function
                    println!("The impossible happened! Also, if you see this, scold me for having bad software design skills");
                }   
            } 

        }
    }
}

fn process_line(options: &ExncOptions, line: &[u8], buffer: &mut Vec<u8>) -> Result<(), ExncError> {
    line_to_buffer(&options.mode, line, buffer)?;
    send_data(&options.sock, &buffer, &options.dest);
    buffer.clear();
    Ok(())
}

fn process_lines<T: Iterator<Item = std::io::Result<String>>>(options: &ExncOptions, lines: T) {
    let mut buffer = Vec::new();
    for line in lines { 
        match process_line(options, line.unwrap().as_bytes(), &mut buffer) {
            Ok(_) => {}, // TODO: is this the right pattern?
            Err(error) => {
                println!("[ERROR] {:?}, processing next line...", error);
                continue;
            }
        }
    }
}

fn test() {
    let mut buffer = Vec::new();

    let _result = line_to_buffer(&OperatingMode::InputIsBinary, b"test_buffer", &mut buffer);
    assert_eq!(buffer, [116, 101, 115, 116, 95, 98, 117, 102, 102, 101, 114]);

    let mut asciibuffer = Vec::new();
    let result = line_to_buffer(&OperatingMode::InputIsHex, b"should fail", &mut asciibuffer);
    assert_eq!(result, Err(ExncError::HexDecodeError));

    let result = line_to_buffer(&OperatingMode::InputIsHex, b"ff00ffe", &mut asciibuffer);
    assert_eq!(result, Err(ExncError::HexDecodeError));

}

fn process_options(options: &ExncOptions) {
    
}

fn main() {
    let options = get_cli_options();
    process_stdin(&options);
}
