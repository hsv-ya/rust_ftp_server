//=======================================================================================================================
//ACTIVE FTP SERVER Start-up Code for Assignment 1 (WinSock 2)

//This code gives parts of the answers away.
//Firstly, you must change parts of this program to make it IPv6-compliant (replace all data structures that work only with IPv4).
//This step would require creating a makefile, as the IPv6-compliant functions require data structures that can be found only by linking with the appropritate library files. 
//The sample TCP server codes will help you accomplish this.

//OVERVIEW
//The connection is established by ignoring USER and PASS, but sending the appropriate 3 digit codes back
//only the active FTP mode connection is implemented (watch out for firewall issues - do not block your own FTP server!).

//The ftp LIST command is fully implemented, in a very naive way using redirection and a temporary file.
//The list may have duplications, extra lines etc, don't worry about these. You can fix it as an exercise, 
//but no need to do that for the assignment.
//In order to implement RETR you can use the LIST part as a startup.  RETR carries a filename, 
//so you need to replace the name when opening the file to send.

//STOR is also a few steps away, use your implementation of RETR and invert it to save the file on the server's dir
//=======================================================================================================================

use std::env;
use std::net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs};
//use std::str::FromStr;
use std::io::{self, Write, Read};
//use std::io::prelude::*;
//use std::ptr;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

/*
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

const SYSTEM_COMMAND_DEL: &str = "del";
const SYSTEM_COMMAND_MKDIR: &str = "mkdir";
const SYSTEM_COMMAND_RMDIR: &str = "rmdir";
const SYSTEM_COMMAND_RENAME: &str = "rename";
*/
static SHOW_DEBUG_MESSAGE: AtomicBool = AtomicBool::new(false);
static mut CONVERT_KIRILLICA: bool = false;

const DEFAULT_PORT: &str = "21";
//const BUFFER_SIZE: usize = 1024;
//const FILENAME_SIZE: usize = 1024;
//const BIG_BUFFER_SIZE: usize = 65535;


// Arguments:
//      0:  Program name
//      1:  Port number
//      2:  Debug mode (true/false)
//      3:  Use convert kirillica file and directory name between Android and Windows 7 (true/false)
fn main() -> std::io::Result<()> {
    let argc = std::env::args().len();
    let argv: Vec<String> = std::env::args().collect();

    set_debug(debug_mode(argc, &argv));

    unsafe { CONVERT_KIRILLICA = convert_kirillica(argc, &argv); }

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

    let _result: Option<SocketAddr> = None;
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

// Returns true if user indicated that convert kirillica should be on.
fn convert_kirillica(argc: usize, argv: &[String]) -> bool {
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
            }
            Err(e) => panic!("Error listening for connections: {}", e),
        }
    }

    println!("SERVER SHUTTING DOWN...");

    Ok(())
}

// Accepts new clients and deals with commands.
fn handle_clients(mut s: TcpStream) -> i32 {
    show_client_info(&s);

    if !send_message(&s, "220 FTP Server ready.\r\n") {
        close_client_connection(&s);
        return 0;
    }

    let mut success = true;
    let mut authroised_login: bool = false;
    //let mut sDataActive: TcpStream = "";
    let client_id = 1;
    let mut current_directory = String::new();
    let mut name_file_for_rename = String::new();

    while success {
        success = communicate_with_client(&mut s, /*&sDataActive,*/ &mut authroised_login, &client_id, &mut current_directory, &mut name_file_for_rename);
    }

    close_client_connection(&s);

    0
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
fn communicate_with_client(s: &mut TcpStream, /*sDataActive: &TcpStream,*/ authroised_login: &mut bool, _client_id: &u64, _current_directory: &mut str, _name_file_for_rename: &mut str) -> bool {
    let mut receive_buffer = Vec::new();
    let mut user_name = Vec::new();
    let mut password = Vec::new();

    let mut receipt_successful = receive_message(s, &mut receive_buffer);
    if !receipt_successful {
        return receipt_successful;
    }

    let mut success;

    let maybe_command = String::from_utf8_lossy(&receive_buffer[..4]);

    if maybe_command == "USER" {
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
    }

    else if maybe_command == "PASS" {
        success = command_password(s, &mut receive_buffer, &mut password, *authroised_login);
    }

    else if maybe_command == "SYST" {
        success = command_system_information(s);
    }

    else if maybe_command == "QUIT" {
        success = command_quit();
    }
/*
    else if maybe_command == "PORT" {
        success = command_data_port(s, sDataActive, receive_buffer);
    }

    else if maybe_command == "LIST" {
        success = command_list(s, sDataActive, client_id, current_directory);
    }

    else if maybe_command == "RETR" {
        success = command_retrieve(s, sDataActive, receive_buffer, current_directory);
    }

    else if maybe_command == "STOR" {
        success = command_store(s, sDataActive, receive_buffer, current_directory);
    }

    else if maybe_command == "CWD " {
        success = command_change_working_directory(s, receive_buffer, current_directory);
    }

    else if maybe_command == "DELE" {
        success = command_delete(s, receive_buffer);
    }

    else if maybe_command == "MKD " {
        success = command_make_directory(s, receive_buffer, current_directory);
    }

    else if maybe_command == "RMD " {
        success = command_delete_directory(s, receive_buffer);
    }

    else if maybe_command == "TYPE" {
        success = command_type(s, receive_buffer);
    }

    else if maybe_command == "FEAT" {
        success = command_feat(s);
    }
    
    else if maybe_command == "OPTS" {
        success = command_opts(s, receive_buffer);
    }

    else if maybe_command == "RNFR" {
        success = command_rename_from(s, receive_buffer, name_file_for_rename);
    }

    else if maybe_command == "RNTO" {
        success = command_rename_to(s, receive_buffer, name_file_for_rename);
    }
*/
    else {
        success = command_unknown(s);
    }

    success
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

    println!("User: \"{:?}\" attempting to login.", user_name);

    *authroised_login = is_valid_user_name(&user_name);

    if *authroised_login {
        println!("User name valid. Password required.");

        return send_message(s, "331 Authorised login requested, please specify the password.\r\n");
    } else {
        println!("User name unauthorised. Public access only.");

        return send_message(s, "331 Public login requested, please specify email as password.\r\n");
    }
}

// Send message to client, returns true if message was sended.
fn send_message(mut s: &TcpStream, send_buffer: &str) -> bool {
    match s.write(send_buffer.as_bytes()) {
        Ok(bytes) => {
            if is_debug() {
                print!("---> {}", send_buffer);
            }
            bytes > 0
        }
        Err(_) => false
    }
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
        return password == "334";
    } else {
        return is_email_address(password);
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
/*
// Client sent PORT command, returns false if fails.
fn command_data_port(s: &TcpStream, sDataActive: &TcpStream, receive_buffer: &mut Vec<u8>) -> bool {
    std::cout << "===================================================" << std::endl;
    std::cout << "\tActive FTP mode, the client is listening..." << std::endl;

    char ipBuffer[40];
    char portBuffer[6];

    memset(&ipBuffer, 0, 40);
    memset(&portBuffer, 0, 6);

    bool success = get_client_ip_and_port(s, receive_buffer, ipBuffer, portBuffer);
    if !success {
        return send_argument_syntax_error(s);
    }

    struct addrinfo *result = NULL;

    success = getClientAddressInfoActive(s, result, ipBuffer, portBuffer);
    if !success {
        freeaddrinfo(result);
        
        return sendFailedActiveConnection(s);
    }

    success = allocateDataTransferSocket(&sDataActive, result);
    if !success {
        closesocket(sDataActive);
        freeaddrinfo(result);
        
        return sendFailedActiveConnection(s);
    }

    success = connectDataTransferSocket(sDataActive, result);
    if !success {
        closesocket(sDataActive);
        freeaddrinfo(result);

        return sendFailedActiveConnection(s);
    }

    char send_buffer[BUFFER_SIZE];
    memset(&send_buffer, 0, BUFFER_SIZE);

    sprintf(send_buffer,"200 PORT Command successful.\r\n");
    int bytes = send(s, send_buffer, strlen(send_buffer), 0);

    if is_debug() {
        std::cout << "---> " << send_buffer;
    }

    if bytes < 0 {
        return false;
    }

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: Connected to client's data connection." << std::endl;
    }

    success
}

// Gets the client's IP and port number for active connection.
fn get_client_ip_and_port(s: &TcpStream, receive_buffer: &str) -> io::Result<(String, String)> {
    let parts: Vec<&str> = receive_buffer.split(',').collect();

    if parts.len() != 6 || !receive_buffer.starts_with("PORT ") {
        return send_argument_syntax_error(s);
    }

    let active_ip: Vec<u8> = parts[1..5]
        .iter()
        .map(|&s| s.parse::<u8>().unwrap())
        .collect();

    let active_port: Vec<u16> = parts[5..]
        .iter()
        .map(|&s| s.parse::<u16>().unwrap())
        .collect();

    let ip_buffer = format!("{}.{}.{}.{}", active_ip[0], active_ip[1], active_ip[2], active_ip[3]);
    println!("\tClient's IP is {}", ip_buffer);

    let port_decimal = (active_port[0] << 8) + active_port[1];
    let port_buffer = port_decimal.to_string();
    println!("\tClient's Port is {}", port_buffer);

    Ok((ip_buffer, port_buffer))
}

fn send_argument_syntax_error(s: &TcpStream) -> bool {
    send_message(s, "501 Syntax error in arguments.\r\n")
}

/*fn send_argument_syntax_error(s: &std::net::TcpStream) -> io::Result<(String, String)> {
    let message_error = "Argument syntax error";
    if is_debug() {
        writeln!(s, message_error).unwrap();
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, message_error))
}*/

// Gets the servers address information based on arguments.
fn get_client_address_info_active(s: &TcpStream, ip_buffer: &str, port_buffer: &str) -> Result<SocketAddr, String> {
    let hints = libc::addrinfo {
        ai_family: libc::AF_INET,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: 0,
        ai_flags: 0,
        ai_canonname: ptr::null_mut(),
        ai_addr: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };

    let mut result: *mut libc::addrinfo = ptr::null_mut();
    let i_result = unsafe { libc::getaddrinfo(ip_buffer.as_ptr() as *const i8, port_buffer.as_ptr() as *const i8, &hints, &mut result) };

    if i_result != 0 {
        eprintln!("getaddrinfo() for client failed: {}", i_result);
        return Err(format!("getaddrinfo failed with error: {}", i_result));
    }

    if is_debug() {
        println!("<<<DEBUG INFO>>>: Client address information created.");
    }

    let addr = unsafe { (*result).ai_addr };
    let socket_addr = unsafe { *(addr as *const SocketAddr) };

    unsafe { libc::freeaddrinfo(result) };

    Ok(socket_addr)
}

// Allocates the socket for data transfer..
fn allocateDataTransferSocket(sDataActive: &TcpStream, result: &addrinfo) -> bool
{
    sDataActive = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if sDataActive == INVALID_SOCKET {
        std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;

        return false;
    }

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: Data transfer socket allocated." << std::endl;
    }

    true
}

// Bind data transfer socket to result address.
fn connect_data_transfer_socket(sDataActive: &TcpStream, result: &addrinfo) -> bool {
    let iResult = connect(sDataActive, result->ai_addr, (int) result->ai_addrlen);

    if iResult == SOCKET_ERROR {
        std::cout << "Active connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(sDataActive);

        return false;
    }

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: Data transfer socket connected." << std::endl;
    }

    true
}

// Sends the client a message to say data connection failed.
fn send_failed_active_connection(s: &TcpStream) -> bool {
    return send_message(s, "425 Something is wrong, can't start active connection.\r\n");
}

// Client sent LIST command, returns false if fails.
fn command_list(s: &TcpStream, sDataActive: &TcpStream, client_id: u64, current_directory: &str) -> bool {
    char tmpDir[FILENAME_SIZE] = { 0 };
    char* pathTemp = getenv("TEMP");

    sprintf(tmpDir, "%s\\%lu_tmpDir.txt", pathTemp, client_id);

    int successLevel = sendFile(s, sDataActive, tmpDir, client_id, current_directory);
    if successLevel != 1 {
        closesocket(sDataActive);

        return successLevel;
    }

    closesocket(sDataActive);

    send_message(s, "226 Directory send OK.\r\n")
}

// Sends specified file to client.
fn send_file(s: &TcpStream, sDataActive: &TcpStream, fileName: &str, client_id: u64, current_directory: &str) -> i32 {
    char tmpDir[FILENAME_SIZE] = { 0 };
    char tmpDir_DIR[FILENAME_SIZE] = { 0 };
    char tmpDir_FILE[FILENAME_SIZE] = { 0 };
    char tmpDir_dirDirectory[FILENAME_SIZE] = { "dir /A:D /B" };
    char tmpDir_dirFiles[FILENAME_SIZE] = { "dir /A:-D /-C" };
    char* pathTemp = NULL;

    if client_id {
        std::cout << "Client has requested the directory listing." << std::endl;

        pathTemp = getenv("TEMP");

        sprintf(tmpDir, "%s\\%lu_tmpDir.txt", pathTemp, client_id);
        sprintf(tmpDir_DIR, "%s\\%lu_tmpDir2.txt", pathTemp, client_id);
        sprintf(tmpDir_FILE, "%s\\%lu_tmpDir3.txt", pathTemp, client_id);

        strcat(tmpDir_dirDirectory, " >");
        strcat(tmpDir_dirDirectory, tmpDir_DIR);

        strcat(tmpDir_dirFiles, " >");
        strcat(tmpDir_dirFiles, tmpDir_FILE);

        char bufferForNewFileName[FILENAME_SIZE];
        memset(&bufferForNewFileName, 0, FILENAME_SIZE);

        if !g_convertKirillica {
            strcpy(bufferForNewFileName, current_directory);
        } else {
            simple_conv(current_directory, strlen(current_directory), bufferForNewFileName, FILENAME_SIZE, true);
        }

        // Save directory information in temp file.
        execute_system_command(tmpDir_dirDirectory, bufferForNewFileName);

        if is_debug() {
            std::cout << "<<<DEBUG INFO>>>: " << tmpDir_dirDirectory << " " << bufferForNewFileName << std::endl;
        }

        execute_system_command(tmpDir_dirFiles, bufferForNewFileName);

        if is_debug() {
            std::cout << "<<<DEBUG INFO>>>: " << tmpDir_dirFiles << " " << bufferForNewFileName << std::endl;
        }

        FILE *fInDIR = fopen(tmpDir, "w");

        FILE *fInDirectory = fopen(tmpDir_DIR, "r");

        char tmpBuffer[BUFFER_SIZE];
        char tmpBufferDir[BUFFER_SIZE];
        bool isFirst = true;

        while !feof(fInDirectory) {
            memset(&tmpBuffer, 0, BUFFER_SIZE);
            if NULL == fgets(tmpBuffer, BUFFER_SIZE, fInDirectory) {
                break;
            }
            killLastCRLF(tmpBuffer);
            memset(&tmpBufferDir, 0, BUFFER_SIZE);
            strcpy(tmpBufferDir, "drw-rw-rw-    1 user       group        512 Oct 15  2024 ");
            if !g_convertKirillica {
                strcat(tmpBufferDir, tmpBuffer);
            } else {
                char bufferForNewFileName[FILENAME_SIZE];
                simple_conv(tmpBuffer, strlen(tmpBuffer), bufferForNewFileName, FILENAME_SIZE, false);
                strcat(tmpBufferDir, bufferForNewFileName);
            }
            if !isFirst {
                fputs("\n", fInDIR);
            } else {
                isFirst = false;
            }
            fputs(tmpBufferDir, fInDIR);
            if is_debug() {
                std::cout << tmpBufferDir << std::endl;
            }
            if ferror(fInDIR) {
                break;
            }
        }

        fclose(fInDirectory);

        FILE *fInFiles = fopen(tmpDir_FILE, "r");

        int skipLines = 5;
        while !feof(fInFiles) && skipLines > 0 {
            memset(&tmpBuffer, 0, BUFFER_SIZE);
            if NULL == fgets(tmpBuffer, BUFFER_SIZE, fInFiles) {
                break;
            }
            skipLines--;
        }

        int iDay, iMonths, iYear, iHour, iMinute;
        unsigned long ulFileSize;
        char tmpFileName[FILENAME_SIZE];
        char tmpBufferFile[FILENAME_SIZE];

        while !feof(fInFiles) {
            memset(&tmpBuffer, 0, BUFFER_SIZE);
            if NULL == fgets(tmpBuffer, BUFFER_SIZE, fInFiles) {
                break;
            }
            if isNumerical(tmpBuffer[0])  {
                memset(&tmpFileName, 0, FILENAME_SIZE);
                sscanf(tmpBuffer, "%2d.%2d.%4d  %2d:%2d %17lu %*s", &iDay, &iMonths, &iYear, &iHour, &iMinute, &ulFileSize);
                strcpy(tmpFileName, tmpBuffer + 36);
                killLastCRLF(tmpFileName);
                memset(&tmpBufferFile, 0, FILENAME_SIZE);
                sprintf(tmpBufferFile, "-rw-rw-rw-    1 user       group %10lu %s %2d  %4d ", ulFileSize, g_sMonths[iMonths - 1], iDay, iYear);
                if !g_convertKirillica  {
                    strcat(tmpBufferFile, tmpFileName);
                } else {
                    char bufferForNewFileName[FILENAME_SIZE];
                    simple_conv(tmpFileName, strlen(tmpFileName), bufferForNewFileName, FILENAME_SIZE, false);
                    strcat(tmpBufferFile, bufferForNewFileName);
                }
                if !isFirst {
                    fputs("\n", fInDIR);
                } else {
                    isFirst = false;
                }
                fputs(tmpBufferFile, fInDIR);
                if is_debug() {
                    std::cout << tmpBufferFile << std::endl;
                }
                if ferror(fInDIR) {
                    break;
                }
            }
        }

        fclose(fInFiles);

        fclose(fInDIR);
    } else {
        std::cout << "Client has requested to retrieve the file: \"" << fileName << "\"." << std::endl;
    }

    char send_buffer[BUFFER_SIZE];
    memset(&send_buffer, 0, BUFFER_SIZE);

    FILE *fIn = NULL;

    if client_id {
        fIn = fopen(fileName, "rb");
    } else {
        char fileNameFull[FILENAME_SIZE];
        memset(&fileNameFull, 0, FILENAME_SIZE);

        strcpy(fileNameFull, current_directory);

        if strlen(fileNameFull) > 0 {
            strcat(fileNameFull, "\\");
        }
        strcat(fileNameFull, fileName);

        if !g_convertKirillica {
            fIn = fopen(fileNameFull, "rb");
        } else {
            char bufferForNewFileName[FILENAME_SIZE];
            simple_conv(fileNameFull, strlen(fileNameFull), bufferForNewFileName, FILENAME_SIZE, true);
            fIn = fopen(bufferForNewFileName, "rb");
        }
    }

    if fIn == NULL {
        std::cout << "The file: \"" << fileName << "\" does not exist." << std::endl;

        sprintf(send_buffer, "550 File name invalid.\r\n");
        int bytes = send(s, send_buffer, strlen(send_buffer), 0);

        if is_debug() {
            std::cout << "---> " << send_buffer;
        }

        if bytes < 0 {
            return 0;
        }

        return -1;
    } else {
        sprintf(send_buffer, "150 Data connection ready. \r\n");
        int bytes = send(s, send_buffer, strlen(send_buffer), 0);

        if is_debug() {
            std::cout << "---> " << send_buffer;
        }

        if bytes < 0 {
            fclose(fIn);

            if client_id {
                if !is_debug() {
                    execute_system_command(systemCommandDEL, tmpDir);
                    execute_system_command(systemCommandDEL, tmpDir_DIR);
                    execute_system_command(systemCommandDEL, tmpDir_FILE);
                }    
            }

            return 0;
        }
    }

    char tempBuffer[BIG_BUFFER_SIZE + 1];

    while !feof(fIn) {
        size_t result = fread(tempBuffer, 1, BIG_BUFFER_SIZE, fIn);

        // send buffer to client
        size_t sent = 0;
        while sent < result {
            int n = send(sDataActive, tempBuffer + sent, result - sent, 0);

            if (n == -1) {
                fclose(fIn);

                if client_id {
                    if !is_debug() {
                        execute_system_command(systemCommandDEL, tmpDir);
                        execute_system_command(systemCommandDEL, tmpDir_DIR);
                        execute_system_command(systemCommandDEL, tmpDir_FILE);
                    }
                }

                return 0;
            }

            sent += n;
        }
    }

    fclose(fIn);

    if client_id  {
        if !is_debug() {
            execute_system_command(systemCommandDEL, tmpDir);
            execute_system_command(systemCommandDEL, tmpDir_DIR);
            execute_system_command(systemCommandDEL, tmpDir_FILE);
        }
    }

    std::cout << "File sent successfully."<< std::endl;

    return 1;
}

// return '0' if not have error.
fn execute_system_command(commandNameWithKeys: &str, fileName: &str) -> i32 {
    char executeCommand[FILENAME_SIZE];
    memset(&executeCommand, 0, FILENAME_SIZE);

    strcpy(executeCommand, commandNameWithKeys);

    strcat(executeCommand, " ");

    if NULL != strchr(fileName, ' ') {
        strcat(executeCommand, "\"");
    }

    strcat(executeCommand, fileName);

    if NULL != strchr(fileName, ' ') {
        strcat(executeCommand, "\"");
    }

    if is_debug() {
        std::cout << "Execute command: " << executeCommand << std::endl;
    }

    return system(executeCommand);
}

// Client sent RETR command, returns false if fails.
fn command_retrieve(s: &TcpStream, sDataActive: &TcpStream, receive_buffer: &str, current_directory: &str) -> bool {
    char fileName[FILENAME_SIZE];
    memset(&fileName, 0, FILENAME_SIZE);

    remove_command(receive_buffer, fileName);

    bool success = sendFile(s, sDataActive, fileName, 0, current_directory);
    if !success {
        closesocket(sDataActive);

        return success;
    }

    closesocket(sDataActive);

    send_message(s, "226 File transfer complete.\r\n")
}

// Client sent STORE command, returns false if fails.
fn command_store(s: &TcpStream, sDataActive: &TcpStream, receive_buffer: &str, current_directory: &str) -> bool {
    char fileName[FILENAME_SIZE];
    memset(&fileName, 0, FILENAME_SIZE);

    removeCommand(receive_buffer, fileName);

    bool success = saveFile(s, sDataActive, fileName, current_directory);
    if !success {
        closesocket(sDataActive);

        return success;
    }

    closesocket(sDataActive);

    send_message(s, "226 File transfer complete.\r\n")
}

// Sends specified file to client.
fn save_file(s: &TcpStream, sDataActive: &TcpStream, fileName: &str, current_directory: &str) -> bool {
    std::cout << "Client has requested to store the file: \"" << fileName << "\"." << std::endl;

    char send_buffer[BUFFER_SIZE];
    memset(&send_buffer, 0, BUFFER_SIZE);

    sprintf(send_buffer, "150 Data connection ready.\r\n");
    int bytes = send(s, send_buffer, strlen(send_buffer), 0);

    if is_debug() {
        std::cout << "---> " << send_buffer;
    }

    if bytes < 0 {
        return false;
    }

    char fileNameFull[FILENAME_SIZE];
    memset(&fileNameFull, 0, FILENAME_SIZE);

    strcat(fileNameFull, current_directory);

    if strlen(fileNameFull) > 0 {
        strcat(fileNameFull, "\\");
    }

    strcat(fileNameFull, fileName);

    std::ofstream fOut;

    if !g_convertKirillica {
        fOut.open(fileNameFull, std::ofstream::binary);
    } else {
        char fileNameFullNorm[FILENAME_SIZE];
        simple_conv(fileNameFull, strlen(fileNameFull), fileNameFullNorm, FILENAME_SIZE, true);
        fOut.open(fileNameFullNorm, std::ofstream::binary);
    }

    char tempBuffer[BIG_BUFFER_SIZE];
    int sizeBuffer = 0;
    bool moreFile = true;

    while moreFile {
        moreFile = receiveFileContents(sDataActive, tempBuffer, sizeBuffer);

        if sizeBuffer > 0 {
            fOut.write(tempBuffer, sizeBuffer);
        }
    }

    fOut.close();

    std::cout << "File saved successfully."<< std::endl;

    true
}

// Receives message and saves it in receive buffer, returns false if connection ended.
fn receive_file_contents(sDataActive: &TcpStream, receive_buffer: &str, sizeBuffer: &i32) -> bool {
    int i = 0;
    int bytes = 0;

    bool fileToRead = true;

    while fileToRead && i < BIG_BUFFER_SIZE - 1 {
        bytes = recv(sDataActive, receive_buffer + i, BIG_BUFFER_SIZE - 1 - i, 0);

        if (bytes == SOCKET_ERROR) || (bytes == 0) {
            fileToRead = false;

            break;
        }

        i += bytes;
    }

    sizeBuffer = i;

    if (bytes == SOCKET_ERROR) || (bytes == 0) {
        return false;
    }

    true
}

// Client sent CWD command, returns false if connection ended.
fn command_change_working_directory(s: &TcpStream, receive_buffer: &str, current_directory: &str) -> bool {
    remove_command(receive_buffer, current_directory);

    replace_backslash(current_directory);

    send_message(s, "250 Directory successfully changed.\r\n")
}

// Client sent DELETE command, returns false if connection ended.
fn command_delete(s: &TcpStream, receive_buffer: &str) -> bool {
    char fileName[FILENAME_SIZE];
    memset(&fileName, 0, FILENAME_SIZE);

    remove_command(receive_buffer, fileName, 5);

    replace_backslash(fileName);

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);

    if !g_convertKirillica {
        strcpy(bufferForNewName, fileName);
    } else {
        simple_conv(fileName, strlen(fileName), bufferForNewName, FILENAME_SIZE, true);
    }

    execute_system_command(systemCommandDEL, bufferForNewName);

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandDEL << " " << fileName << std::endl;
    }

    send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent MKD command, returns false if connection ended.
fn command_make_directory(s: &TcpStream, receive_buffer: &str, current_directory: &str) -> bool {
    char directoryName[FILENAME_SIZE];
    memset(&directoryName, 0, FILENAME_SIZE);

    remove_command(receive_buffer, directoryName);

    replace_backslash(directoryName);

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);

    if !g_convertKirillica {
        strcpy(bufferForNewName, directoryName);
    } else {
        simple_conv(directoryName, strlen(directoryName), bufferForNewName, FILENAME_SIZE, true);
    }

    execute_system_command(systemCommandMKDIR, bufferForNewName);

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandMKDIR << " " << directoryName << std::endl;
    }

    char send_buffer[BUFFER_SIZE];
    memset(&send_buffer, 0, BUFFER_SIZE);

    sprintf(send_buffer, "257 '/%s' directory created\r\n", directoryName);

    send_message(s, send_buffer)
}

// Client sent RMD command, returns false if connection ended.
fn command_delete_directory(s: &TcpStream, receive_buffer: &str) -> bool {
    char directoryName[FILENAME_SIZE];
    memset(&directoryName, 0, FILENAME_SIZE);

    remove_command(receive_buffer, directoryName);

    replace_backslash(directoryName);

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);

    if !g_convertKirillica {
        strcpy(bufferForNewName, directoryName);
    } else {
        simple_conv(directoryName, strlen(directoryName), bufferForNewName, FILENAME_SIZE, true);
    }

    execute_system_command(systemCommandRMDIR, bufferForNewName);

    if is_debug() {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandRMDIR << " " << directoryName << std::endl;
    }

    send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent TYPE command, returns false if connection ended.
fn command_type(s: &TcpStream, receive_buffer: &str) -> bool {
    char typeName[BUFFER_SIZE];
    memset(&typeName, 0, BUFFER_SIZE);

    remove_command(receive_buffer, typeName);

    char send_buffer[BUFFER_SIZE];
    memset(&send_buffer, 0, BUFFER_SIZE);

    sprintf(send_buffer, "200 Type set to %s.\r\n", typeName);

    send_message(s, send_buffer)
}

// Client sent FEAT command, returns false if fails.
fn command_feat(s: &TcpStream) -> bool {
    send_message(s, "211-Extensions supported\r\n UTF8\r\n211 end\r\n")
}

// Client sent OPTS command, returns false if connection ended.
fn command_opts(s: &TcpStream, receive_buffer: &str) -> bool {
    char optsName[BUFFER_SIZE];
    memset(&optsName, 0, BUFFER_SIZE);

    remove_command(receive_buffer, optsName);

    if strncmp(optsName, "UTF8 ON", 8) == 0 {
        return send_message(s, "200 UTF8 ON.\r\n");
    } else {
        return send_argument_syntax_error(s);
    }
}

// Client sent RNFR command, returns false if connection ended.
fn command_rename_from(s: &TcpStream, receive_buffer: &str, name_file_for_rename: &str) -> bool {
    name_file_for_rename[0] = '\0';

    remove_command(receive_buffer, name_file_for_rename, 5);

    send_message(s, "350 Requested file action pending further information.\r\n")
}

// Client sent RNTO command, returns false if connection ended.
fn command_rename_to(s: &TcpStream, receive_buffer: &str, name_file_for_rename: &str) -> bool {
    char nameFileToRename[FILENAME_SIZE];
    memset(&nameFileToRename, 0, FILENAME_SIZE);

    remove_command(receive_buffer, nameFileToRename, 5);

    if (0 == strlen(name_file_for_rename)) || (0 == strlen(nameFileToRename)) {
        name_file_for_rename[0] = '\0';

        return send_message(s, "503 Bad sequence of commands.\r\n");
    }

    char bufferForCommandAndFirstParameter[FILENAME_SIZE];
    memset(&bufferForCommandAndFirstParameter, 0, FILENAME_SIZE);

    strcpy(bufferForCommandAndFirstParameter, systemCommandRENAME);
    strcat(bufferForCommandAndFirstParameter, " ");

    if NULL != strchr(name_file_for_rename, ' ') {
        strcat(bufferForCommandAndFirstParameter, "\"");
    }

    replace_backslash(name_file_for_rename);

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);

    if !g_convertKirillica {
        strcpy(bufferForNewName, name_file_for_rename);
    } else {
        simple_conv(name_file_for_rename, strlen(name_file_for_rename), bufferForNewName, FILENAME_SIZE, true);
    }

    strcat(bufferForCommandAndFirstParameter, bufferForNewName);

    if NULL != strchr(name_file_for_rename, ' ') {
        strcat(bufferForCommandAndFirstParameter, "\"");
    }

    memset(&bufferForNewName, 0, FILENAME_SIZE);

    replace_backslash(nameFileToRename);

    char *pch = nameFileToRename;
    
    while NULL != strchr(pch, '\\') {
        pch = strchr(pch, '\\') + 1;
    }

    if !g_convertKirillica {
        strcpy(bufferForNewName, pch);
    } else {
        simple_conv(pch, strlen(pch), bufferForNewName, FILENAME_SIZE, true);
    }

    int error = execute_system_command(bufferForCommandAndFirstParameter, bufferForNewName);

    name_file_for_rename[0] = '\0';

    if error {
        return send_message(s, "503 Bad sequence of commands.\r\n");
    } else {
        return send_message(s, "250 Requested file action okay, file renamed.\r\n");
    }
}
*/
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

    return at_index != -1 && dot_index != -1 && at_index < dot_index;
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
/*
// Delete <CR> and <LF> in end of string.
fn kill_last_cr_lf(buffer: &str) {
    while 0 < strlen(buffer) && 
         ('\r' == buffer[strlen(buffer) - 1] ||
          '\n' == buffer[strlen(buffer) - 1]) {
        buffer[strlen(buffer) - 1] = 0;
    }
}

// Replace '/' to '\' for Windows
fn replace_backslash(buffer: &str) {
    size_t i = 0;
    size_t length = strlen(buffer);

    for (; i < length; i++) {
        if '/' == buffer[i] {
            buffer[i] = '\\';
        }
    }
}

// Converting kirillic characters between Android and Windows 7
fn simple_conv(inString: &str, inLen: i32, outString: &str, outMaxLen: i32, tudaSuda: bool) {
    const ALL_SYMBOLS_FOR_CONVERT = (31 + 31 + 4 + 1);

    static table_for_convert_Tuda: [&str; ALL_SYMBOLS_FOR_CONVERT] = {
        // small
        r#"\xd0\xb9\xE9"#,
        r#"\xd1\x86\xF6"#,
        r#"\xd1\x83\xF3"#,
        r#"\xd0\xba\xEA"#,
        r#"\xd0\xb5\xE5"#,
        r#"\xd0\xbd\xED"#,
        r#"\xd0\xb3\xE3"#,
        r#"\xd1\x88\xF8"#,
        r#"\xd1\x89\xF9"#,
        r#"\xd0\xb7\xE7"#,
        r#"\xd1\x85\xF5"#,
        r#"\xd1\x84\xF4"#,
        r#"\xd1\x8b\xFB"#,
        r#"\xd0\xb2\xE2"#,
        r#"\xd0\xb0\xE0"#,
        r#"\xd0\xbf\xEF"#,
        r#"\xd1\x80\xF0"#,
        r#"\xd0\xbe\xEE"#,
        r#"\xd0\xbb\xEB"#,
        r#"\xd0\xb4\xE4"#,
        r#"\xd0\xb6\xE6"#,
        r#"\xd1\x8d\xFD"#,
        r#"\xd1\x8f\xFF"#,
        r#"\xd1\x87\xF7"#,
        r#"\xd1\x81\xF1"#,
        r#"\xd0\xbc\xEC"#,
        r#"\xd0\xb8\xE8"#,
        r#"\xd1\x82\xF2"#,
        r#"\xd1\x8c\xFC"#,
        r#"\xd0\xb1\xE1"#,
        r#"\xd1\x8e\xFE"#,
        // big
        r#"\xd0\x99\xC9"#,
        r#"\xd0\xa6\xD6"#,
        r#"\xd0\xa3\xD3"#,
        r#"\xd0\x9a\xCA"#,
        r#"\xd0\x95\xC5"#,
        r#"\xd0\x9d\xCD"#,
        r#"\xd0\x93\xC3"#,
        r#"\xd0\xa8\xD8"#,
        r#"\xd0\xa9\xD9"#,
        r#"\xd0\x97\xC7"#,
        r#"\xd0\xa5\xD5"#,
        r#"\xd0\xa4\xD4"#,
        r#"\xd0\xab\xDB"#,
        r#"\xd0\x92\xC2"#,
        r#"\xd0\x90\xC0"#,
        r#"\xd0\x9f\xCF"#,
        r#"\xd0\xa0\xD0"#,
        r#"\xd0\x9e\xCE"#,
        r#"\xd0\x9b\xCB"#,
        r#"\xd0\x94\xC4"#,
        r#"\xd0\x96\xC6"#,
        r#"\xd0\xad\xDD"#,
        r#"\xd0\xaf\xDF"#,
        r#"\xd0\xa7\xD7"#,
        r#"\xd0\xa1\xD1"#,
        r#"\xd0\x9c\xCC"#,
        r#"\xd0\x98\xC8"#,
        r#"\xd0\xa2\xD2"#,
        r#"\xd0\xac\xDC"#,
        r#"\xd0\x91\xC1"#,
        r#"\xd0\xae\xDE"#,

        r#"\xd0\xaa\xda"#, // big "b
        r#"\xd1\x8a\xfa"#, // small "b
        r#"\xd0\x81\xa8"#, // big :E
        r#"\xd1\x91\xb8"#, // small :e

        r#"\xe2\x84\x96\xb9"# // N
    };

    static table_for_convert_Suda: [&str; ALL_SYMBOLS_FOR_CONVERT] = {
        // small
        r#"\xd0\xb9\xA9"#,
        r#"\xd1\x86\xE6"#,
        r#"\xd1\x83\xE3"#,
        r#"\xd0\xba\xAA"#,
        r#"\xd0\xb5\xA5"#,
        r#"\xd0\xbd\xAD"#,
        r#"\xd0\xb3\xA3"#,
        r#"\xd1\x88\xE8"#,
        r#"\xd1\x89\xE9"#,
        r#"\xd0\xb7\xA7"#,
        r#"\xd1\x85\xE5"#,
        r#"\xd1\x84\xE4"#,
        r#"\xd1\x8b\xEB"#,
        r#"\xd0\xb2\xA2"#,
        r#"\xd0\xb0\xA0"#,
        r#"\xd0\xbf\xAF"#,
        r#"\xd1\x80\xE0"#,
        r#"\xd0\xbe\xAE"#,
        r#"\xd0\xbb\xAB"#,
        r#"\xd0\xb4\xA4"#,
        r#"\xd0\xb6\xA6"#,
        r#"\xd1\x8d\xED"#,
        r#"\xd1\x8f\xEF"#,
        r#"\xd1\x87\xE7"#,
        r#"\xd1\x81\xE1"#,
        r#"\xd0\xbc\xAC"#,
        r#"\xd0\xb8\xA8"#,
        r#"\xd1\x82\xE2"#,
        r#"\xd1\x8c\xEC"#,
        r#"\xd0\xb1\xA1"#,
        r#"\xd1\x8e\xEE"#,
        // big
        r#"\xd0\x99\x89"#,
        r#"\xd0\xa6\x96"#,
        r#"\xd0\xa3\x93"#,
        r#"\xd0\x9a\x8A"#,
        r#"\xd0\x95\x85"#,
        r#"\xd0\x9d\x8D"#,
        r#"\xd0\x93\x83"#,
        r#"\xd0\xa8\x98"#,
        r#"\xd0\xa9\x99"#,
        r#"\xd0\x97\x87"#,
        r#"\xd0\xa5\x95"#,
        r#"\xd0\xa4\x94"#,
        r#"\xd0\xab\x9B"#,
        r#"\xd0\x92\x82"#,
        r#"\xd0\x90\x80"#,
        r#"\xd0\x9f\x8F"#,
        r#"\xd0\xa0\x90"#,
        r#"\xd0\x9e\x8E"#,
        r#"\xd0\x9b\x8B"#,
        r#"\xd0\x94\x84"#,
        r#"\xd0\x96\x86"#,
        r#"\xd0\xad\x9D"#,
        r#"\xd0\xaf\x9F"#,
        r#"\xd0\xa7\x97"#,
        r#"\xd0\xa1\x91"#,
        r#"\xd0\x9c\x8C"#,
        r#"\xd0\x98\x88"#,
        r#"\xd0\xa2\x92"#,
        r#"\xd0\xac\x9C"#,
        r#"\xd0\x91\x81"#,
        r#"\xd0\xae\x9E"#,

        r#"\xd0\xaa\xda"#, // big "b
        r#"\xd1\x8a\xfa"#, // small "b
        r#"\xd0\x81\xa8"#, // big :E
        r#"\xd1\x91\xb8"#, // small :e

        r#"\xe2\x84\x96\xfc"# // N
    };

    int pos = 0;

    if tudaSuda {
        for (int i = 0; i < inLen;) {
            if b'\xd0' == inString[i] || b'\xd1' == inString[i] {
                bool isFound = false;

                for (int q = 0; q < ALL_SYMBOLS_FOR_CONVERT - 1; q++) {
                    if table_for_convert_Tuda[q][0] == inString[i] && table_for_convert_Tuda[q][1] == inString[i + 1] {
                        outString[pos] = table_for_convert_Tuda[q][2];
                        isFound = true;
                        break;
                    }
                }

                if isFound {
                    pos++;
                    i++;
                }
            } else if b'\xe2' == inString[i] {
                bool isFound = false;

                for (int q = ALL_SYMBOLS_FOR_CONVERT - 1; q < ALL_SYMBOLS_FOR_CONVERT; q++) {
                    if table_for_convert_Tuda[q][0] == inString[i] && table_for_convert_Tuda[q][1] == inString[i + 1] && table_for_convert_Tuda[q][2] == inString[i + 2] {
                        outString[pos] = table_for_convert_Tuda[q][3];
                        isFound = true;
                        break;
                    }
                }

                if isFound {
                    pos++;
                    i += 2;
                }
            } else {
                outString[pos] = inString[i];
                pos++;
            }

            i++;

            if pos > outMaxLen {
                outString[outMaxLen - 1] = 0;
                break;
            }
        }
    } else {
        for (int i = 0; i < inLen;) {
            bool isFound = false;

            for (int q = 0; q < ALL_SYMBOLS_FOR_CONVERT - 1; q++) {
                if table_for_convert_Suda[q][2] == inString[i] {
                    outString[pos] = table_for_convert_Suda[q][0];
                    outString[pos + 1] = table_for_convert_Suda[q][1];
                    isFound = true;
                    break;
                }
            }

            if isFound {
                pos++;
            } else {
                bool isFound2 = false;
                
                for (int q = ALL_SYMBOLS_FOR_CONVERT - 1; q < ALL_SYMBOLS_FOR_CONVERT; q++) {
                    if table_for_convert_Suda[q][3] == inString[i] {
                        outString[pos] = table_for_convert_Suda[q][0];
                        outString[pos + 1] = table_for_convert_Suda[q][1];
                        outString[pos + 2] = table_for_convert_Suda[q][2];
                        isFound2 = true;
                        break;
                    }
                }

                if isFound2 {
                    pos += 2;
                } else {
                    outString[pos] = inString[i];
                }
            }

            pos++;
            i++;

            if pos > outMaxLen {
                outString[outMaxLen - 1] = 0;
                break;
            }
        }
    }
    if pos < outMaxLen {
        outString[pos] = 0;
    }
}
*/
