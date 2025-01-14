/*
 * ACTIVE FTP SERVER Start-up Code (WinSock 2) simple rewrite on Rust
 *
 * This code gives parts of the answers away.
 * The sample TCP server codes will help you accomplish this.
 *
 * OVERVIEW
 * Only the active FTP mode connection is implemented (watch out for firewall
 * issues - do not block your own FTP server!).
 *
 * Only IP4
 *
 * The ftp LIST command is fully implemented, in a very naive way using
 * redirection and a temporary file.
*/


use std::env;
use std::net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs};
use std::io::{self, Write, Read};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs::File;
use std::process::Command;
use chrono::{Utc, Datelike, NaiveDateTime};
use filetime::{FileTime, set_file_mtime};


const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

const SYSTEM_COMMAND_DEL: &str = "del";
const SYSTEM_COMMAND_MKDIR: &str = "mkdir";
const SYSTEM_COMMAND_RMDIR: &str = "rmdir";
const SYSTEM_COMMAND_RENAME: &str = "rename";

static SHOW_DEBUG_MESSAGE: AtomicBool = AtomicBool::new(false);
static CONVERT_CYRILLIC: AtomicBool = AtomicBool::new(false);

const DEFAULT_PORT: &str = "21";
const BIG_BUFFER_SIZE: usize = 65535;


// Arguments:
//      0:  Program name
//      1:  Port number
//      2:  Debug mode (true/false)
//      3:  Use convert cyrillic file and directory name between Android and Windows 7 (true/false)
fn main() -> std::io::Result<()> {
    let argc = std::env::args().len();
    let argv: Vec<String> = std::env::args().collect();

    set_debug(debug_mode(argc, &argv));

    set_convert_cyrillic(convert_cyrillic(argc, &argv));

    if env::var("TEMP").is_err() {
        if is_debug() {
            writeln!(io::stdout(), "Error, not find environment <TEMP>!!")?;
        }
        return Err(io::Error::new(io::ErrorKind::Other, "TEMP not found"));
    } else {
        if let Ok(temp) = env::var("TEMP") {
            if temp.len() > 50 {
                if is_debug() {
                    writeln!(io::stdout(), "Error, very long size for environment <TEMP>!!")?;
                }
                return Err(io::Error::new(io::ErrorKind::Other, "TEMP too long"));
            }
        }
    }

    let result = get_server_address_info(argc, &argv);
    if result == Err(0) {
        return Err(io::Error::new(io::ErrorKind::Other, "Error getting server address info"));
    }

    let mut listener = TcpListener::bind(result.unwrap()).unwrap();

    show_server_info();

    server_listen(&mut listener)
}

fn set_debug(b: bool) {
    SHOW_DEBUG_MESSAGE.store(b, Ordering::Relaxed);
}

fn is_debug() -> bool {
    SHOW_DEBUG_MESSAGE.load(Ordering::Relaxed)
}

// Returns true if user indicated that debug mode should be on.
fn debug_mode(argc: usize, argv: &[String]) -> bool {
    if argc > 2 {
        if argv[2] == "true" {
            return true;
        }
    }

    false
}

fn set_convert_cyrillic(b: bool) {
    CONVERT_CYRILLIC.store(b, Ordering::Relaxed);
}

fn is_convert_cyrillic() -> bool {
    CONVERT_CYRILLIC.load(Ordering::Relaxed)
}

// Returns true if user indicated that convert cyrillic should be on.
fn convert_cyrillic(argc: usize, argv: &[String]) -> bool {
    if argc > 3 {
        if argv[3] == "true" {
            return true;
        }
    }

    false
}

fn show_server_info() {
    println!("===============================");
    println!("     159.334 FTP Server        ");
    println!("===============================");
}

// Gets the servers address information based on arguments.
fn get_server_address_info(argc: usize, argv: &[String]) -> Result<SocketAddr, i32> {
    let addr = if argc > 1 {
        format!("0.0.0.0:{}", argv[1])
    } else {
        format!("0.0.0.0:{}", DEFAULT_PORT)
    };

    let socket_addr = addr.to_socket_addrs()
        .map_err(|_| 3)?
        .next()
        .ok_or(3)?;

    if is_debug() {
        println!("<<<DEBUG INFO>>>: Server address information created.");
    }

    Ok(socket_addr)
}

// Listen for client communication and deal with it accordingly.
fn server_listen(listener: &mut TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                thread::spawn(move || handle_clients(s));
            },
            Err(e) => panic!("Error listening for connections: {}", e),
        }
    }

    println!("SERVER SHUTTING DOWN...");

    Ok(())
}

// Accepts new clients and deals with commands.
fn handle_clients(mut s: TcpStream) {
    show_client_info(&s);

    if !send_message(&s, "220 FTP Server ready.\r\n") {
        close_client_connection(&s);
        return;
    }

    let mut success = true;
    let mut authroised_login: bool = false;
    let mut connect_to = String::new();
    let client_id = s.peer_addr().unwrap().port();
    let mut current_directory = String::new();
    let mut name_file_or_dir_for_rename = String::new();

    while success {
        success = communicate_with_client(
            &mut s,
            &mut connect_to,
            &mut authroised_login,
            client_id,
            &mut current_directory,
            &mut name_file_or_dir_for_rename);
    }

    close_client_connection(&s);
}

// Takes incoming connection and assigns new socket.
fn show_client_info(s: &TcpStream) {
    println!("A client has been accepted.");

    let client_host = &s.peer_addr().unwrap().ip().to_string();
    let client_service = &s.peer_addr().unwrap().port().to_string();

    print!("Connected to client with IP address: {}", client_host);
    println!(", at Port: {}", client_service);
}

// Receive and handle messages from client, returns false if client ends connection.
fn communicate_with_client(s: &mut TcpStream, connect_to: &mut String, authroised_login: &mut bool, client_id: u16, current_directory: &mut String, name_file_or_dir_for_rename: &mut String) -> bool {
    let mut receive_buffer = Vec::new();
    let mut user_name = Vec::new();
    let mut password = Vec::new();

    let mut receipt_successful = receive_message(s, &mut receive_buffer);
    if !receipt_successful {
        return receipt_successful;
    }

    let mut success;

    let maybe_command: &str = &String::from_utf8_lossy(&receive_buffer[..4]).to_string();

    match maybe_command {
        "USER" => {
            let mut i_attempts = 0;

            loop {
                success = command_user_name(s, &mut receive_buffer, &mut user_name, authroised_login);

                if !success {
                    i_attempts += 1;

                    receipt_successful = receive_message(s, &mut receive_buffer);
                    if !receipt_successful {
                        return receipt_successful;
                    }
                }
                if success || i_attempts >= 3 {
                    break;
                }
            }
            success
        }, 

        "PASS" => command_password(s, &mut receive_buffer, &mut password, *authroised_login),
        "SYST" => command_system_information(s),
        "QUIT" => command_quit(),
        "PORT" => command_port(s, connect_to, &mut receive_buffer),
        "LIST" => command_list(s, connect_to, client_id, current_directory),
        "NLST" => command_list(s, connect_to, client_id, current_directory),
        "RETR" => command_retrieve(s, connect_to, &mut receive_buffer, current_directory),
        "STOR" => command_store(s, connect_to, &mut receive_buffer, current_directory),
        "CWD " => command_change_working_directory(s, &mut receive_buffer, current_directory),
        "DELE" => command_delete(s, &mut receive_buffer),
        "MKD " => command_make_directory(s, &mut receive_buffer),
        "RMD " => command_delete_directory(s, &mut receive_buffer),
        "TYPE" => command_type(s, &mut receive_buffer),
        "FEAT" => command_feat(s),
        "OPTS" => command_opts(s, &mut receive_buffer),
        "RNFR" => command_rename_from(s, &mut receive_buffer, name_file_or_dir_for_rename),
        "RNTO" => command_rename_to(s, &mut receive_buffer, name_file_or_dir_for_rename),
        "MFMT" => command_mfmt(s, &mut receive_buffer),
        _ => command_unknown(s)
    }
}

// Receives message and saves it in receive buffer, returns false if connection ended.
fn receive_message(mut s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut bytes;
    let mut buffer: [u8; 1] = [0];

    loop {
        bytes = match s.read(&mut buffer) {
            Ok(b) => b,
            Err(_) => 0,
        };

        if bytes == 0 {
            break;
        }

        receive_buffer.push(buffer[0]);

        if buffer[0] == b'\n' {
            receive_buffer.pop();
            break;
        }

        else if buffer[0] == b'\r' {
            receive_buffer.pop();
        }
    }

    if bytes == 0 {
        return false;
    }

    if is_debug() {
        println!("<--- {:?}", String::from_utf8(receive_buffer.to_vec()));
    }

    true
}

// Client sent USER command, returns false if fails.
fn command_user_name(s: &TcpStream, receive_buffer: &mut Vec<u8>, user_name: &mut Vec<u8>, authroised_login: &mut bool) -> bool {
    remove_command(receive_buffer, user_name, 4);

    let user_name = String::from_utf8_lossy(&user_name);

    println!("User: \"{}\" attempting to login.", user_name);

    *authroised_login = is_valid_user_name(&user_name);

    if *authroised_login {
        println!("User name valid. Password required.");

        send_message(s, "331 Authorised login requested, please specify the password.\r\n")
    } else {
        println!("User name unauthorised. Public access only.");

        send_message(s, "331 Public login requested, please specify email as password.\r\n")
    }
}

// Send message to client, returns true if message was sended.
fn send_message(mut s: &TcpStream, send_buffer: &str) -> bool {
    let mut bytes: usize = send_buffer.len();
    match s.write_all(send_buffer.as_bytes()) {
        Ok(()) => {
            if is_debug() {
                print!("---> {}", send_buffer);
            }
        },
        Err(_) => bytes = 0
    };
    bytes == send_buffer.len()
}

// Returns true if valid user name.
fn is_valid_user_name(user_name: &str) -> bool {
    user_name == "nhreyes"
}

// Client sent PASS command, returns false if fails.
fn command_password(s: &TcpStream, receive_buffer: &mut Vec<u8>, password: &mut Vec<u8>, authroised_login: bool) -> bool {
    remove_command(receive_buffer, password, 4);

    let valid_password = is_valid_password(password, authroised_login);

    let send_buffer: &str;

    if valid_password {
        println!("Password valid. User logged in.");

        send_buffer = "230 Login successful.\r\n";
    } else {
        println!("Password invalid. Login failed.");

        send_buffer = "530 Login authentication failed.\r\n";
    }

    if !send_message(s, send_buffer) {
        return false;
    }

    valid_password
}

// Returns true if valid password.
fn is_valid_password(password: &mut Vec<u8>, authroised_login: bool) -> bool {
    if authroised_login {
        let password = String::from_utf8_lossy(&password);
        password == "334"
    } else {
        is_email_address(password)
    }
}

// Client sent SYST command, returns false if fails.
fn command_system_information(s: &TcpStream) -> bool {
    println!("System information requested.");

    send_message(s, "215 Windows Type: WIN64\r\n")
}

// Client sent QUIT command, returns false if fails.
fn command_quit() -> bool {
    println!("Client has quit the session.");

    false
}

// Client sent PORT command, returns false if fails.
fn command_port(s: &TcpStream, connect_to: &mut String, receive_buffer: &mut Vec<u8>) -> bool {
    println!("===================================================");
    println!("\tActive FTP mode, the client is listening...");

    *connect_to = get_client_ip_and_port(receive_buffer);

    if connect_to.len() == 0 {
        send_argument_syntax_error(s)
    } else {
        send_message(s, "200 PORT Command successful.\r\n")
    }
}

// Gets the client's IP and port number for active connection.
fn get_client_ip_and_port(receive_buffer: &mut Vec<u8>) -> String {
    let temp_string = String::from_utf8_lossy(&receive_buffer[5..]);
    let parts: Vec<&str> = temp_string.split(',').collect();

    if parts.len() != 6 || !receive_buffer.starts_with(b"PORT ") {
        return "".to_string();
    }

    if is_debug() {
        println!("{:?}", parts);
    }

    let active_ip: Vec<u8> = parts[..4]
        .iter()
        .map(|&s| s.parse::<u8>().unwrap())
        .collect();

    if is_debug() {
        println!("{:?}", active_ip);
    }

    let active_port: Vec<u16> = parts[4..]
        .iter()
        .map(|&s| s.parse::<u16>().unwrap())
        .collect();

    if is_debug() {
        println!("{:?}", active_port);
    }

    let ip_buffer = format!("{}.{}.{}.{}", active_ip[0], active_ip[1], active_ip[2], active_ip[3]);
    println!("\tClient's IP is {}", ip_buffer);

    let port_decimal = (active_port[0] << 8) + active_port[1];
    let port_buffer = port_decimal.to_string();
    println!("\tClient's Port is {}", port_buffer);

    let mut result2 = String::new();
    result2 += ip_buffer.as_str();
    result2 += ":";
    result2 += port_buffer.as_str();

    result2
}

fn send_argument_syntax_error(s: &TcpStream) -> bool {
    send_message(s, "501 Syntax error in arguments.\r\n")
}

// Sends the client a message to say data connection failed.
fn send_failed_active_connection(s: &TcpStream) -> bool {
    send_message(s, "425 Something is wrong, can't start active connection.\r\n")
}

// Client sent LIST command, returns false if fails.
fn command_list(s: &TcpStream, connect_to: &mut String, client_id: u16, current_directory: &mut String) -> bool {
    let path_temp = get_temp_directory();

    let tmp = format!("{}\\{}_tmp_dir.txt", path_temp, client_id);

    let result = send_file(s, connect_to, tmp.as_str(), client_id, current_directory.as_str());

    match result {
        Ok(_) => {},
        Err(_) => return false
    };

    send_message(s, "226 Directory send OK.\r\n")
}

fn get_temp_directory() -> String {
    match env::var("TEMP") {
        Ok(val) => val,
        Err(_) => "".to_string()
    }
}

fn delete_temp_files(file1: &str, file2: &str, file3: &str) {
    execute_system_command(SYSTEM_COMMAND_DEL, file1, "");
    execute_system_command(SYSTEM_COMMAND_DEL, file2, "");
    execute_system_command(SYSTEM_COMMAND_DEL, file3, "");
}

// Sends specified file to client.
fn send_file(s: &TcpStream, connect_to: &mut String, file_name: &str, client_id: u16, current_directory: &str) -> Result<i32, std::io::Error> {
    let mut tmp: String = String::new();
    let mut tmp_directory: String = String::new();
    let mut tmp_file: String = String::new();
    let mut tmp_dir_directory: String = "dir /A:D /B".to_string();
    let mut tmp_dir_files: String = "dir /A:-D /-C".to_string();

    if client_id > 0 {
        println!("Client has requested the directory listing.");

        let now = Utc::now();
        let (_is_common_era, year) = now.year_ce();

        let path_temp = get_temp_directory();

        tmp = format!("{}\\{}_tmp_dir.txt", path_temp, client_id).to_string();
        tmp_directory = format!("{}\\{}_tmp_dir2.txt", path_temp, client_id).to_string();
        tmp_file = format!("{}\\{}_tmp_dir3.txt", path_temp, client_id).to_string();

        tmp_dir_directory += " >";
        tmp_dir_directory += &tmp_directory;

        tmp_dir_files += " >";
        tmp_dir_files += &tmp_file;

        if is_debug() {
            println!("<<<DEBUG INFO>>>: {} {}", tmp_dir_files, current_directory);
        }

        execute_system_command(tmp_dir_files.as_str(), current_directory, "");

        if is_debug() {
            println!("<<<DEBUG INFO>>>: {} {}", tmp_dir_directory, current_directory);
        }

        execute_system_command(tmp_dir_directory.as_str(), current_directory, "");

        let mut f_in_dir = File::create(tmp.as_str())?;

        let f_in_directory = File::open(tmp_directory.as_str())?;

        let mut is_first = true;

        let mut buffer: Vec<u8> = Vec::new();

        for iter in f_in_directory.bytes() {
            let byte = iter.unwrap();
            if byte == b'\r' {
                continue;
            } else if byte == b'\n' {
                let mut tmp_buffer_dir: String = "drw-rw-rw-    1 user       group        512 Oct 15  2024 ".to_string();
                if !is_convert_cyrillic() {
                    let line = String::from_utf8_lossy(&buffer[0..]);
                    tmp_buffer_dir += &line;
                } else {
                    let mut tmp_new_file_name: Vec<u8> = Vec::new();
                    simple_conv(buffer.clone(), &mut tmp_new_file_name, false);
                    let str_tmp_new_file_name = String::from_utf8_lossy(&tmp_new_file_name[0..]);
                    tmp_buffer_dir += &str_tmp_new_file_name;
                }
                if !is_first {
                    let _ = f_in_dir.write_all("\n".as_bytes());
                } else {
                    is_first = false;
                }
                let _ = f_in_dir.write_all(tmp_buffer_dir.as_bytes());
                if is_debug() {
                    println!("{}", tmp_buffer_dir);
                }
                buffer.clear();
            } else {
                buffer.push(byte);
            }
        }

        let result = File::open(tmp_file.as_str());
        let f_in_files;
        match result {
            Ok(f) => f_in_files = f,
            Err(e) => panic!("{:?} '{}'", e, tmp_file)
        }

        let mut skip_lines = 5;
        let mut tmp_file_name: String;
        let mut tmp_buffer_file: String;

        for iter in f_in_files.bytes() {
            let byte = iter.unwrap();
            if byte == b'\r' {
                continue;
            } else if byte == b'\n' {
                if skip_lines > 0 {
                    skip_lines -= 1;
                    buffer.clear();
                    continue;
                }

                if is_numerical(buffer[0]) {
                    let line = String::from_utf8_lossy(&buffer[0..36]);

                    let v: Vec<&str> = line.split_whitespace().collect();
                    let tmp_date = v[0];

                    let i_day = (tmp_date[0..=1]).to_string().parse::<u8>().unwrap();
                    let i_month = (tmp_date[3..=4]).to_string().parse::<usize>().unwrap();
                    let i_year = (tmp_date[6..=9]).to_string().parse::<u32>().unwrap();

                    let tmp_time = v[1];
                    let i_hour = (tmp_time[0..=1]).to_string().parse::<u8>().unwrap();
                    let i_minute = (tmp_time[3..=4]).to_string().parse::<u8>().unwrap();

                    let tmp_file_size = v[2];
                    let file_size: usize = tmp_file_size.parse::<usize>().unwrap();

                    let tmp_file_name_vec: Vec<u8> = (&buffer[36..]).into();

                    if year == i_year {
                        tmp_buffer_file = format!("-rw-rw-rw-    1 user       group {:10} {} {:02} {:02}:{:02} ", file_size, MONTHS[i_month - 1], i_day, i_hour, i_minute).to_string();
                    } else {
                        tmp_buffer_file = format!("-rw-rw-rw-    1 user       group {:10} {} {:02}  {:04} ", file_size, MONTHS[i_month - 1], i_day, i_year).to_string();
                    }
                    if !is_convert_cyrillic() {
                        tmp_file_name = String::from_utf8_lossy(&buffer[36..]).to_string();
                        tmp_buffer_file += &tmp_file_name;
                    } else {
                        let mut tmp_new_file_name_vec: Vec<u8> = Vec::new();
                        simple_conv(tmp_file_name_vec, &mut tmp_new_file_name_vec, false);
                        let tmp_new_file_name = String::from_utf8_lossy(&tmp_new_file_name_vec[0..]);
                        tmp_buffer_file += &tmp_new_file_name;
                    }
                    if !is_first {
                        let _ = f_in_dir.write_all("\n".as_bytes());
                    } else {
                        is_first = false;
                    }
                    let _ = f_in_dir.write_all(tmp_buffer_file.as_bytes());
                    if is_debug() {
                        println!("{}", tmp_buffer_file);
                    }
                }
                buffer.clear();
            } else {
                buffer.push(byte);
            }
        }

        let _ = f_in_dir.write_all("\n".as_bytes());
    } else {
        println!("Client has requested to retrieve the file: \"{}\".", file_name);
    }

    let mut file_name_for_open: String;

    if client_id > 0 {
        file_name_for_open = tmp.clone();
    } else {
        file_name_for_open = current_directory.to_string();

        if file_name_for_open.len() > 0 {
            file_name_for_open += "\\";
        }

        file_name_for_open += file_name;
    }

    let result = File::open(file_name_for_open.as_str());
    let mut f_in;

    match result {
        Err(_) => {
            println!("The file: \"{}\" does not exist.", file_name_for_open);

            if !send_message(s, "550 File name invalid.\r\n") {
                return Ok(0);
            }

            return Ok(-1);
        },
        Ok(f) => {
            f_in = f;
            if !send_message(s, "150 Data connection ready.\r\n") {
                if client_id > 0 {
                    if !is_debug() {
                        delete_temp_files(&tmp, &tmp_directory, &tmp_file);
                    }
                }

                return Ok(0);
            }
        }
    }

    let mut temp_buffer = [0; BIG_BUFFER_SIZE];
    let mut send_to;

    match TcpStream::connect(connect_to.as_str()) {
        Ok(stream) => send_to = stream,
        Err(_) => {
            if client_id > 0 {
                if !is_debug() {
                    delete_temp_files(&tmp, &tmp_directory, &tmp_file);
                }
            }
            return Ok(0);
        }
    }

    loop {
        let result = f_in.read(&mut temp_buffer[..]);

        let read_bytes;

        match result {
            Ok(n) => read_bytes = n,
            Err(_) => read_bytes = 0
        }

        if read_bytes == 0 {
            break;
        }

        let bytes = match send_to.write_all(&temp_buffer[..read_bytes]) {
            Ok(()) => read_bytes,
            Err(_) => 0,
        };

        if bytes != read_bytes {
            if client_id > 0 {
                if !is_debug() {
                    delete_temp_files(&tmp, &tmp_directory, &tmp_file);
                }
            }
            return Ok(0);
        }
    }

    if client_id > 0 {
        if !is_debug() {
            delete_temp_files(&tmp, &tmp_directory, &tmp_file);
        }
    }

    println!("File sent successfully.");

    Ok(1)
}

// return '0' if not have error.
fn execute_system_command(command_name_with_keys: &str, file_name_first: &str, file_name_second: &str) -> i32 {
    use std::os::windows::process::CommandExt;

    let mut cmd_args = String::new();

    let all_args = command_name_with_keys.split(" ");
    let mut is_first = true;
    for arg in all_args {
        if is_first {
            cmd_args = arg.to_string();
            is_first = false;
        } else {
            cmd_args.push_str(" ");
            cmd_args.push_str(arg);
        }
    }

    if file_name_first.len() > 0 {
        cmd_args.push_str(" ");
        if file_name_first.contains(" ") {
            cmd_args.push_str("\"");
        }
        cmd_args.push_str(file_name_first);
        if file_name_first.contains(" ") {
            cmd_args.push_str("\"");
        }
    }

    if file_name_second.len() > 0 {
        cmd_args.push_str(" ");
        if file_name_second.contains(" ") {
            cmd_args.push_str("\"");
        }
        cmd_args.push_str(file_name_second);
        if file_name_second.contains(" ") {
            cmd_args.push_str("\"");
        }
    }

    if is_debug() {
        println!("Execute command: {}", cmd_args);
    }

    let status = Command::new("cmd.exe")
            .arg("/C")
            .raw_arg(&format!("\"{cmd_args}\""))
            .status()
            .expect("command failed to start");

    match status.code() {
        Some(code) => code,
        None => -1
    }
}

// Client sent RETR command, returns false if fails.
fn command_retrieve(s: &TcpStream, connect_to: &mut String, receive_buffer: &mut Vec<u8>, current_directory: &mut String) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    let tmp = String::from_utf8_lossy(&tmp_vec).to_string();

    let result = send_file(s, connect_to, tmp.as_str(), 0, current_directory.as_str());

    match result {
        Ok(_) => {},
        Err(_) => return false
    };

    send_message(s, "226 File transfer complete.\r\n")
}

// Client sent STORE command, returns false if fails.
fn command_store(s: &TcpStream, connect_to: &mut String, receive_buffer: &mut Vec<u8>, current_directory: &mut String) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    let tmp = String::from_utf8_lossy(&tmp_vec).to_string();

    let result = save_file(s, connect_to, tmp.as_str(), current_directory.as_str());

    if !result {
        return result;
    }

    send_message(s, "226 File transfer complete.\r\n")
}

// Sends specified file to client.
fn save_file(s: &TcpStream, connect_to: &mut String, file_name: &str, current_directory: &str) -> bool {
    println!("Client has requested to store the file: \"{}\".", file_name);

    let mut recv_from;

    match TcpStream::connect(connect_to.as_str()) {
        Ok(stream) => recv_from = stream,
        Err(_) => {
            send_failed_active_connection(s);
            return false;
        }
    }

    if !send_message(s, "150 Data connection ready.\r\n") {
        return false;
    }

    let mut file_name_full: String = current_directory.to_string();

    if file_name_full.len() > 0 {
        file_name_full += "\\";
    }

    file_name_full += file_name;

    let result = File::create(file_name_full.as_str());
    let mut f_out_file;
    match result {
        Ok(f) => f_out_file = f,
        Err(_) => return false
    }

    let mut temp_buffer: Vec<u8> = vec![0; BIG_BUFFER_SIZE];

    loop {
        let recv_bytes = recv_from.read(&mut temp_buffer[..]).unwrap();

        if recv_bytes > 0 {
            let _ = f_out_file.write_all(&temp_buffer[..recv_bytes]);
        } else {
            break;
        }
    }

    println!("File saved successfully.");

    true
}

// Client sent CWD command, returns false if connection ended.
fn command_change_working_directory(s: &TcpStream, receive_buffer: &mut Vec<u8>, current_directory: &mut String) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    replace_backslash(&mut tmp_vec);

    *current_directory = String::from_utf8_lossy(&tmp_vec[0..]).to_string();

    if current_directory == "\\" {
        *current_directory = "".to_string();
    }

    send_message(s, "250 Directory successfully changed.\r\n")
}

// Client sent DELETE command, returns false if connection ended.
fn command_delete(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 5);

    replace_backslash(&mut tmp_vec);

    let tmp = String::from_utf8_lossy(&tmp_vec[0..]).to_string();

    execute_system_command(SYSTEM_COMMAND_DEL, tmp.as_str(), "");

    if is_debug() {
        println!("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_DEL, tmp);
    }

    send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent MKD command, returns false if connection ended.
fn command_make_directory(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    replace_backslash(&mut tmp_vec);

    let tmp = String::from_utf8_lossy(&tmp_vec[0..]).to_string();

    execute_system_command(SYSTEM_COMMAND_MKDIR, tmp.as_str(), "");

    if is_debug() {
        println!("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_MKDIR, tmp);
    }

    let send_buffer = format!("257 '/{}' directory created\r\n", tmp);

    send_message(s, &send_buffer)
}

// Client sent RMD command, returns false if connection ended.
fn command_delete_directory(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    replace_backslash(&mut tmp_vec);

    let tmp = String::from_utf8_lossy(&tmp_vec[0..]).to_string();

    execute_system_command(SYSTEM_COMMAND_RMDIR, tmp.as_str(), "");

    if is_debug() {
        println!("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_RMDIR, tmp);
    }

    send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent TYPE command, returns false if connection ended.
fn command_type(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp = Vec::new();

    remove_command(receive_buffer, &mut tmp, 4);

    let type_name = String::from_utf8_lossy(&tmp[0..]);

    let send_buffer = format!("200 Type set to {}.\r\n", type_name);

    send_message(s, &send_buffer)
}

// Client sent FEAT command, returns false if fails.
fn command_feat(s: &TcpStream) -> bool {
    send_message(s, "211-Extensions supported\r\n UTF8\r\n MFMT\r\n211 end\r\n")
}

// Client sent OPTS command, returns false if connection ended.
fn command_opts(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    let opts_name = String::from_utf8_lossy(&tmp_vec[0..]);

    if opts_name == "UTF8 ON" {
        send_message(s, "200 UTF8 ON.\r\n")
    } else {
        send_argument_syntax_error(s)
    }
}

// Client sent RNFR command, returns false if connection ended.
fn command_rename_from(s: &TcpStream, receive_buffer: &mut Vec<u8>, name_file_or_dir_for_rename: &mut String) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 5);

    replace_backslash(&mut tmp_vec);

    *name_file_or_dir_for_rename = String::from_utf8_lossy(&tmp_vec[0..]).to_string();

    send_message(s, "350 Requested file action pending further information.\r\n")
}

// Client sent RNTO command, returns false if connection ended.
fn command_rename_to(s: &TcpStream, receive_buffer: &mut Vec<u8>, name_file_or_dir_for_rename: &mut String) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 5);

    replace_backslash(&mut tmp_vec);

    let name_file_or_dir_to_rename = String::from_utf8_lossy(&tmp_vec[0..]);

    if (0 == name_file_or_dir_for_rename.len()) || (0 == name_file_or_dir_to_rename.len()) {
        name_file_or_dir_for_rename.clear();

        return send_message(s, "503 Bad sequence of commands.\r\n");
    }

    let mut v: Vec<&str> = name_file_or_dir_to_rename.split("\\").collect();

    let name = v.pop().unwrap();

    let result = execute_system_command(SYSTEM_COMMAND_RENAME, &name_file_or_dir_for_rename, name);

    name_file_or_dir_for_rename.clear();

    if result != 0 {
        send_message(s, "503 Bad sequence of commands.\r\n")
    } else {
        send_message(s, "250 Requested file action okay, file renamed.\r\n")
    }
}

// Client sent MFMT command, returns false if connection ended.
fn command_mfmt(s: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    let mut tmp_vec = Vec::new();

    remove_command(receive_buffer, &mut tmp_vec, 4);

    let mdya = String::from_utf8_lossy(&tmp_vec[0..]);

    let v: Vec<&str> = mdya.split_whitespace().collect();

    let date_time_mfmt = v[0];

    let date_time_for_file = NaiveDateTime::parse_from_str(date_time_mfmt, "%Y%m%d%H%M%S").unwrap();

    let file_name = String::from_utf8_lossy(&tmp_vec[15..]).to_string();

    let mtime = FileTime::from_unix_time(date_time_for_file.and_utc().timestamp(), 0);

    let _ = set_file_mtime(file_name.clone(), mtime);

    let send_buffer = format!("213 Modify={}; {}\r\n", date_time_mfmt, file_name);

    send_message(s, &send_buffer)
}

// Client sent unknown command, returns false if fails.
fn command_unknown(s: &TcpStream) -> bool {
    send_message(s, "550 unrecognised command.\r\n")
}

// Takes a string with a 4 letter command at beginning and saves an output string with this removed.
fn remove_command(input_string: &mut Vec<u8>, output_string: &mut Vec<u8>, skip_characters: usize) {
    let mut i: usize = 0;
    let length: usize = input_string.len();

    while (i + skip_characters + 1) < length {
        output_string.push(input_string[i + skip_characters + 1]);
        i += 1;
    }
}

// Check is inputted string is valid email address (only requires an '@' before a '.').
fn is_email_address(address: &mut Vec<u8>) -> bool {
    // First character must be a-z or A-Z.
    if !is_alphabetical(address[0]) {
        return false;
    }

    let mut at_index: i32 = -1;
    let mut dot_index: i32 = -1;

    let length: usize = address.len();
    let mut i: usize = 1;

    while i < length {
        let c = address[i];

        if !is_alphabetical(c) && !is_numerical(c) {
            if c == b'@' {
                at_index = i as i32;
            } else if c == b'.' {
                dot_index = i as i32;
            } else {
                return false;
            }
        }
        i += 1;
    }

    at_index != -1 && dot_index != -1 && at_index < dot_index
}

// Returns true if the character is alphabetical.
fn is_alphabetical(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

// Returns true if the character is a number.
fn is_numerical(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

// Sends client the closing connection method and closes the socket.
fn close_client_connection(s: &TcpStream) {
    send_message(s, "221 FTP server closed the connection.\r\n");

    println!("Disconnected from client.");
}

// Replace '/' to '\' for Windows
fn replace_backslash(buffer: &mut Vec<u8>) {
    let mut i: usize = 0;

    while i < buffer.len() {
        if '/' as u8 == buffer[i] {
            buffer[i] = '\\' as u8;
        }
        i += 1;
    }
}

// Converting cyrillic characters between Android and Windows 7
fn simple_conv(in_string: Vec<u8>, out_string: &mut Vec<u8>, tuda_suda: bool) {
    const ALL_SYMBOLS_FOR_CONVERT: usize = 31 + 31 + 4 + 1;

    static TABLE_FOR_CONVERT_TUDA: [[u8; 4]; ALL_SYMBOLS_FOR_CONVERT] = [
        // small
        [0xd0, 0xb9, 0xE9, 0],
        [0xd1, 0x86, 0xF6, 0],
        [0xd1, 0x83, 0xF3, 0],
        [0xd0, 0xba, 0xEA, 0],
        [0xd0, 0xb5, 0xE5, 0],
        [0xd0, 0xbd, 0xED, 0],
        [0xd0, 0xb3, 0xE3, 0],
        [0xd1, 0x88, 0xF8, 0],
        [0xd1, 0x89, 0xF9, 0],
        [0xd0, 0xb7, 0xE7, 0],
        [0xd1, 0x85, 0xF5, 0],
        [0xd1, 0x84, 0xF4, 0],
        [0xd1, 0x8b, 0xFB, 0],
        [0xd0, 0xb2, 0xE2, 0],
        [0xd0, 0xb0, 0xE0, 0],
        [0xd0, 0xbf, 0xEF, 0],
        [0xd1, 0x80, 0xF0, 0],
        [0xd0, 0xbe, 0xEE, 0],
        [0xd0, 0xbb, 0xEB, 0],
        [0xd0, 0xb4, 0xE4, 0],
        [0xd0, 0xb6, 0xE6, 0],
        [0xd1, 0x8d, 0xFD, 0],
        [0xd1, 0x8f, 0xFF, 0],
        [0xd1, 0x87, 0xF7, 0],
        [0xd1, 0x81, 0xF1, 0],
        [0xd0, 0xbc, 0xEC, 0],
        [0xd0, 0xb8, 0xE8, 0],
        [0xd1, 0x82, 0xF2, 0],
        [0xd1, 0x8c, 0xFC, 0],
        [0xd0, 0xb1, 0xE1, 0],
        [0xd1, 0x8e, 0xFE, 0],
        // big
        [0xd0, 0x99, 0xC9, 0],
        [0xd0, 0xa6, 0xD6, 0],
        [0xd0, 0xa3, 0xD3, 0],
        [0xd0, 0x9a, 0xCA, 0],
        [0xd0, 0x95, 0xC5, 0],
        [0xd0, 0x9d, 0xCD, 0],
        [0xd0, 0x93, 0xC3, 0],
        [0xd0, 0xa8, 0xD8, 0],
        [0xd0, 0xa9, 0xD9, 0],
        [0xd0, 0x97, 0xC7, 0],
        [0xd0, 0xa5, 0xD5, 0],
        [0xd0, 0xa4, 0xD4, 0],
        [0xd0, 0xab, 0xDB, 0],
        [0xd0, 0x92, 0xC2, 0],
        [0xd0, 0x90, 0xC0, 0],
        [0xd0, 0x9f, 0xCF, 0],
        [0xd0, 0xa0, 0xD0, 0],
        [0xd0, 0x9e, 0xCE, 0],
        [0xd0, 0x9b, 0xCB, 0],
        [0xd0, 0x94, 0xC4, 0],
        [0xd0, 0x96, 0xC6, 0],
        [0xd0, 0xad, 0xDD, 0],
        [0xd0, 0xaf, 0xDF, 0],
        [0xd0, 0xa7, 0xD7, 0],
        [0xd0, 0xa1, 0xD1, 0],
        [0xd0, 0x9c, 0xCC, 0],
        [0xd0, 0x98, 0xC8, 0],
        [0xd0, 0xa2, 0xD2, 0],
        [0xd0, 0xac, 0xDC, 0],
        [0xd0, 0x91, 0xC1, 0],
        [0xd0, 0xae, 0xDE, 0],

        [0xd0, 0xaa, 0xda, 0], // big "b
        [0xd1, 0x8a, 0xfa, 0], // small "b
        [0xd0, 0x81, 0xa8, 0], // big :E
        [0xd1, 0x91, 0xb8, 0], // small :e

        [0xe2, 0x84, 0x96, 0xb9] // N
    ];

    static TABLE_FOR_CONVERT_SUDA: [[u8; 4]; ALL_SYMBOLS_FOR_CONVERT] = [
        // small
        [0xd0, 0xb9, 0xA9, 0],
        [0xd1, 0x86, 0xE6, 0],
        [0xd1, 0x83, 0xE3, 0],
        [0xd0, 0xba, 0xAA, 0],
        [0xd0, 0xb5, 0xA5, 0],
        [0xd0, 0xbd, 0xAD, 0],
        [0xd0, 0xb3, 0xA3, 0],
        [0xd1, 0x88, 0xE8, 0],
        [0xd1, 0x89, 0xE9, 0],
        [0xd0, 0xb7, 0xA7, 0],
        [0xd1, 0x85, 0xE5, 0],
        [0xd1, 0x84, 0xE4, 0],
        [0xd1, 0x8b, 0xEB, 0],
        [0xd0, 0xb2, 0xA2, 0],
        [0xd0, 0xb0, 0xA0, 0],
        [0xd0, 0xbf, 0xAF, 0],
        [0xd1, 0x80, 0xE0, 0],
        [0xd0, 0xbe, 0xAE, 0],
        [0xd0, 0xbb, 0xAB, 0],
        [0xd0, 0xb4, 0xA4, 0],
        [0xd0, 0xb6, 0xA6, 0],
        [0xd1, 0x8d, 0xED, 0],
        [0xd1, 0x8f, 0xEF, 0],
        [0xd1, 0x87, 0xE7, 0],
        [0xd1, 0x81, 0xE1, 0],
        [0xd0, 0xbc, 0xAC, 0],
        [0xd0, 0xb8, 0xA8, 0],
        [0xd1, 0x82, 0xE2, 0],
        [0xd1, 0x8c, 0xEC, 0],
        [0xd0, 0xb1, 0xA1, 0],
        [0xd1, 0x8e, 0xEE, 0],
        // big
        [0xd0, 0x99, 0x89, 0],
        [0xd0, 0xa6, 0x96, 0],
        [0xd0, 0xa3, 0x93, 0],
        [0xd0, 0x9a, 0x8A, 0],
        [0xd0, 0x95, 0x85, 0],
        [0xd0, 0x9d, 0x8D, 0],
        [0xd0, 0x93, 0x83, 0],
        [0xd0, 0xa8, 0x98, 0],
        [0xd0, 0xa9, 0x99, 0],
        [0xd0, 0x97, 0x87, 0],
        [0xd0, 0xa5, 0x95, 0],
        [0xd0, 0xa4, 0x94, 0],
        [0xd0, 0xab, 0x9B, 0],
        [0xd0, 0x92, 0x82, 0],
        [0xd0, 0x90, 0x80, 0],
        [0xd0, 0x9f, 0x8F, 0],
        [0xd0, 0xa0, 0x90, 0],
        [0xd0, 0x9e, 0x8E, 0],
        [0xd0, 0x9b, 0x8B, 0],
        [0xd0, 0x94, 0x84, 0],
        [0xd0, 0x96, 0x86, 0],
        [0xd0, 0xad, 0x9D, 0],
        [0xd0, 0xaf, 0x9F, 0],
        [0xd0, 0xa7, 0x97, 0],
        [0xd0, 0xa1, 0x91, 0],
        [0xd0, 0x9c, 0x8C, 0],
        [0xd0, 0x98, 0x88, 0],
        [0xd0, 0xa2, 0x92, 0],
        [0xd0, 0xac, 0x9C, 0],
        [0xd0, 0x91, 0x81, 0],
        [0xd0, 0xae, 0x9E, 0],

        [0xd0, 0xaa, 0xda, 0], // big "b
        [0xd1, 0x8a, 0xfa, 0], // small "b
        [0xd0, 0x81, 0xa8, 0], // big :E
        [0xd1, 0x91, 0xb8, 0], // small :e

        [0xe2, 0x84, 0x96, 0xfc] // N
    ];

    let in_len = in_string.len();

    if is_debug() {
        for x in &in_string {
            print!("0x{:x}, ", x);
        }
        println!("");
    }

    let mut i: usize = 0;

    if tuda_suda {
        while i < in_len {
            if b'\xd0' == in_string[i] || b'\xd1' == in_string[i] {
                let mut is_found = false;
                let mut q: usize = 0;

                while q < ALL_SYMBOLS_FOR_CONVERT - 1 {
                    if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i + 1] {
                        out_string.push(TABLE_FOR_CONVERT_TUDA[q][2]);
                        is_found = true;
                        break;
                    }

                    q += 1;
                }

                if is_found {
                    i += 1;
                }
            } else if b'\xe2' == in_string[i] {
                let mut is_found = false;
                let mut q = ALL_SYMBOLS_FOR_CONVERT - 1;

                while q < ALL_SYMBOLS_FOR_CONVERT {
                    if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i + 1] && TABLE_FOR_CONVERT_TUDA[q][2] == in_string[i + 2] {
                        out_string.push(TABLE_FOR_CONVERT_TUDA[q][3]);
                        is_found = true;
                        break;
                    }

                    q += 1;
                }

                if is_found {
                    i += 2;
                }
            } else {
                out_string.push(in_string[i]);
            }

            i += 1;
        }
    } else {
        while i < in_len {
            let mut is_found = false;
            let mut q = 0;

            while q < ALL_SYMBOLS_FOR_CONVERT - 1 {
                if TABLE_FOR_CONVERT_SUDA[q][2] == in_string[i] {
                    out_string.push(TABLE_FOR_CONVERT_SUDA[q][0]);
                    out_string.push(TABLE_FOR_CONVERT_SUDA[q][1]);
                    is_found = true;
                    break;
                }
                q += 1;
            }

            if !is_found {
                let mut is_found2 = false;
                let mut q = ALL_SYMBOLS_FOR_CONVERT - 1;

                while q < ALL_SYMBOLS_FOR_CONVERT {
                    if TABLE_FOR_CONVERT_SUDA[q][3] == in_string[i] {
                        out_string.push(TABLE_FOR_CONVERT_SUDA[q][0]);
                        out_string.push(TABLE_FOR_CONVERT_SUDA[q][1]);
                        out_string.push(TABLE_FOR_CONVERT_SUDA[q][2]);
                        is_found2 = true;
                        break;
                    }
                    q += 1;
                }

                if !is_found2 {
                    out_string.push(in_string[i]);
                }
            }

            i += 1;
        }
    }

    if is_debug() {
        for x in out_string {
            print!("0x{:x}, ", x);
        }
        println!("");
    }
}
