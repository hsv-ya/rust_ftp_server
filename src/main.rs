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

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

const SYSTEM_COMMAND_DEL: &str = "del";
const SYSTEM_COMMAND_MKDIR: &str = "mkdir";
const SYSTEM_COMMAND_RMDIR: &str = "rmdir";
const SYSTEM_COMMAND_RENAME: &str = "rename";

static mut CONVERT_KIRILLICA: bool = false;

const DEFAULT_PORT: &str = "21";
const BUFFER_SIZE: usize = 1024;
const FILENAME_SIZE: usize = 1024;
const BIG_BUFFER_SIZE: usize = 65535;


// Arguments:
//      0:  Program name
//      1:  Port number
//      2:  Debug mode (true/false)
//      3:  Use convert kirillica file and directory name between Android and Windows 7 (true/false)
fn main() -> std::io::Result<()> {
    let argc = std::env::args().len();
    let argv: Vec<String> = std::env::args().collect();

    let debug = debug_mode(argc, &argv);

    unsafe { CONVERT_KIRILLICA = convert_kirillica(argc, &argv); }

    if env::var("TEMP").is_err() {
        if debug {
            writeln!(io::stdout(), "Error, not find environment <TEMP>!!")?;
        }
        return Err(io::Error::new(io::ErrorKind::Other, "TEMP not found"));
    } else {
        if let Ok(temp) = env::var("TEMP") {
            if temp.len() > 50 {
                if debug {
                    writeln!(io::stdout(), "Error, very long size for environment <TEMP>!!")?;
                }
                return Err(io::Error::new(io::ErrorKind::Other, "TEMP too long"));
            }
        }
    }

    let result: Option<SocketAddr> = None;
    let result = get_server_address_info(argc, &argv, debug);
    if result == Err(0) {
        return Err(io::Error::new(io::ErrorKind::Other, "Error getting server address info"));
    }

    let listener = TcpListener::bind(result.unwrap()).unwrap();

    show_server_info();

    server_listen(&listener, debug)
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
fn get_server_address_info(argc: usize, argv: &[String], debug: bool) -> Result<SocketAddr, i32> {
    let addr = if argc > 1 {
        format!("0.0.0.0:{}", argv[1])
    } else {
        format!("0.0.0.0:{}", DEFAULT_PORT)
    };

    let socket_addr = addr.to_socket_addrs()
        .map_err(|_| 3)?
        .next()
        .ok_or(3)?;

    if debug {
        println!("<<<DEBUG INFO>>>: Server address information created.");
    }

    Ok(socket_addr)
}

// Listen for client communication and deal with it accordingly.
fn server_listen(listener: &TcpListener, debug: bool) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                accept_clients(&s, debug);
            },
            Err(_e) => panic!("Error listening for connections"),
        }
    }

    println!("SERVER SHUTTING DOWN...");

    Ok(())
}

// Accepts new clients and deals with commands.
fn accept_clients(s: &TcpStream, debug: bool) -> i32 {
    accept_new_client(&s);

    let sendBuffer: &str = "220 FTP Server ready.\r\n\0";
    if !send_message(&s, sendBuffer, debug) {
        close_client_connection(s, debug);
        return 0;
    }

    let mut success = true;
    let authroisedLogin = false;
    //let mut sDataActive: TcpStream = "";
    let clientId = 1;
    let mut currentDirectory = String::new();
    let mut nameFileForRename = String::new();

    while success {
        success = communicate_with_client(&s, /*&sDataActive,*/ authroisedLogin, debug, &clientId, &mut currentDirectory, &mut nameFileForRename);
    }

    close_client_connection(s, debug);

    0
}

// Takes incoming connection and assigns new socket.
fn accept_new_client(s: &TcpStream) {
    println!("A client has been accepted.");

    let clientHost = &s.peer_addr().unwrap().ip().to_string();
    let clientService = &s.peer_addr().unwrap().port().to_string();

    print!("Connected to client with IP address: {}", clientHost);
    println!(", at Port: {}", clientService);
}

// Receive and handle messages from client, returns false if client ends connection.
fn communicate_with_client(s: &TcpStream, /*sDataActive: &TcpStream,*/ authroisedLogin: bool, debug: bool, clientId: &u64, currentDirectory: &mut str, nameFileForRename: &mut str) -> bool
{
    let mut receiveBuffer = Vec::new();
    let mut userName = Vec::new();
    let mut password = Vec::new();

    let mut receiptSuccessful = true;

    receiptSuccessful = receiveMessage(s, &mut receiveBuffer, debug);
    if !receiptSuccessful {
        return receiptSuccessful;
    }

    let mut success = true;

    if receiveBuffer[..5] == *"USER".as_bytes() {
        let mut iAttempts = 0;

        loop
        {
            success = command_user_name(&s, &mut receiveBuffer, &mut userName, authroisedLogin, debug);

            if !success {
                iAttempts += 1;                                                                // Increment number of login attempts.

                receiptSuccessful = receiveMessage(s, &mut receiveBuffer, debug);       // Receives message and saves it in receive buffer.
                if !receiptSuccessful {
                    return receiptSuccessful;                                       // Return that user ended connection.
                }
            }
            if success || iAttempts >= 3 {
                break;
            }
        }
    }

    else if receiveBuffer[..5] == *"PASS".as_bytes() {
        success = command_password(s, &mut receiveBuffer, &mut password, authroisedLogin, debug);
    }

    else if receiveBuffer[..5] == *"SYST".as_bytes() {
        success = command_system_information(s, debug);
    }

    else if receiveBuffer[..5] == *"QUIT".as_bytes() {
        success = command_quit();
    }
/*
    else if (strncmp(receiveBuffer, "PORT", 4) == 0)                                // Check if PORT message received from client.
    {
        success = commandDataPort(s, sDataActive, receiveBuffer, debug);           // Handle command.
    }

    else if (strncmp(receiveBuffer, "LIST", 4) == 0)                                // Check if LIST message received from client.
    {
        success = commandList(s, sDataActive, debug, clientId, currentDirectory);  // Handle command.
    }

    else if (strncmp(receiveBuffer, "RETR", 4) == 0)                                // Check if RETR message received from client.
    {
        success = commandRetrieve(s, sDataActive, receiveBuffer, debug, currentDirectory); // Handle command.
    }

    else if (strncmp(receiveBuffer, "STOR", 4) == 0)                                // Check if STOR message received from client.
    {
        success = commandStore(s, sDataActive, receiveBuffer, debug, currentDirectory); // Handle command.
    }

    else if (strncmp(receiveBuffer, "CWD", 3) == 0)                                 // Check if CWD message received from client.
    {
        success = commandChangeWorkingDirectory(s, receiveBuffer, debug, currentDirectory); // Handle command.
    }

    else if (strncmp(receiveBuffer, "DELE", 4) == 0)                                // Check if DELE message received from client.
    {
        success = commandDelete(s, receiveBuffer, debug);                          // Handle command.
    }

    else if (strncmp(receiveBuffer, "MKD", 3) == 0)                                 // Check if MKD message received from client.
    {
        success = commandMakeDirectory(s, receiveBuffer, debug, currentDirectory); // Handle command.
    }

    else if (strncmp(receiveBuffer, "RMD", 3) == 0)                                 // Check if RMD message received from client.
    {
        success = commandDeleteDirectory(s, receiveBuffer, debug);                 // Handle command.
    }

    else if (strncmp(receiveBuffer, "TYPE", 4) == 0)                                // Check if TYPE message received from client.
    {
        success = commandType(s, receiveBuffer, debug);                            // Handle command.
    }

    else if (strncmp(receiveBuffer, "FEAT", 4) == 0)                                // Check if FEAT message received from client.
    {
        success = commandFeat(s, debug);                                           // Handle command.
    }
    
    else if (strncmp(receiveBuffer, "OPTS", 4) == 0)                                // Check if OPTS message received from client.
    {
        success = commandOpts(s, receiveBuffer, debug);                            // Handle command.
    }

    else if (strncmp(receiveBuffer, "RNFR", 4) == 0)                                // Check if RNFR message received from client.
    {
        success = commandRenameFrom(s, receiveBuffer, nameFileForRename, debug);   // Handle command.
    }

    else if (strncmp(receiveBuffer, "RNTO", 4) == 0)                                // Check if RNTO message received from client.
    {
        success = commandRenameTo(s, receiveBuffer, nameFileForRename, debug);     // Handle command.
    }
*/
    else {
        success = command_unknown(s, debug);
    }

    success
}

// Receives message and saves it in receive buffer, returns false if connection ended.
fn receiveMessage(mut s: &TcpStream, receiveBuffer: &mut Vec<u8>, debug: bool) -> bool {
    let mut i = 0;                                                                      // Index of character of the receive buffer to look at.
    let mut bytes = 0;                                                                  // Response of receive function.

    let mut messageToRead = true;                                                      // If more message to read this is true.
    let mut buffer = [0; 1];

    loop {
        bytes = match s.read(&mut buffer) {
            Ok(b) => b,
            Err(_) => 0,
        };

        if bytes == 0 {
            break;
        } else {
            receiveBuffer.push(buffer[0]);
        }

        if receiveBuffer[i] == b'\n' {
            receiveBuffer[i] = b'\0';
            messageToRead = false;
        }

        else if receiveBuffer[i] != b'\r' {
            i += 1;
        }
    }

    if bytes == 0 {
        return false;
    }

    if debug {
        println!("<--- {:?}\\r\\n", receiveBuffer);
    }

    true
}

// Client sent USER command, returns false if fails.
fn command_user_name(s: &TcpStream, receiveBuffer: &mut Vec<u8>, userName: &mut Vec<u8>, mut authroisedLogin: bool, debug: bool) -> bool
{
    remove_command(receiveBuffer, userName, 4);

    println!("User: \"{:?}\" attempting to login.", userName);

    let validUserName = is_valid_user_name(userName);                                  // Check if user name is valid.

    if validUserName {
        println!("User name valid. Password required.");

        authroisedLogin = true;                                                     // Need authorised password to log in.

        return send_message(s, "331 Authorised login requested, please specify the password.\r\n", debug);
    }
    else                                                                            // User name invalid
    {
        println!("User name unauthorised. Public access only.");

        authroisedLogin = false;                                                    // Don't need authorised password to log in.

        return send_message(s, "331 Public login requested, please specify email as password.\r\n", debug);
    }
}

// Send message to client, returns true if message was sended.
fn send_message(mut s: &TcpStream, send_buffer: &str, debug: bool) -> bool {
    match s.write(send_buffer.as_bytes()) {
        Ok(bytes) => {
            if debug {
                println!("---> {}", send_buffer);
            }
            bytes > 0
        },
        Err(_) => false,
    }
}

// Returns true if valid user name.
fn is_valid_user_name(userName: &mut Vec<u8>) -> bool {
    &*userName == b"nhreyes".as_ref()
}

// Client sent PASS command, returns false if fails.
fn command_password(mut s: &TcpStream, receiveBuffer: &mut Vec<u8>, password: &mut Vec<u8>, authroisedLogin: bool, debug: bool) -> bool {
    remove_command(receiveBuffer, password, 4);

    let validPassword = is_valid_password(password, authroisedLogin);

    let mut sendBuffer: &str = "";

    if validPassword {
        println!("Password valid. User logged in.");

        sendBuffer = "230 Login successful.\r\n";
    } else {
        println!("Password invalid. Login failed.");

        sendBuffer = "530 Login authentication failed.\r\n";
    }

    let bytes = match s.write(sendBuffer.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };

    if debug {
        print!("---> {}", sendBuffer);
    }

    if bytes < 0 {
        return false;
    }

    validPassword
}

// Returns true if valid password.
fn is_valid_password(password: &mut Vec<u8>, authroisedLogin: bool) -> bool {
    if authroisedLogin {
        return &*password == b"334".as_ref();
    } else {
        return is_email_address(password);
    }
}

// Client sent SYST command, returns false if fails.
fn command_system_information(mut s: &TcpStream, debug: bool) -> bool {
    println!("System information requested.");

    let message = "215 Windows Type: WIN64\r\n";
    let bytes = match s.write(message.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };

    if debug {
        print!("---> {}", message);
    }

    if bytes < 0 {
        return false;
    }

    true
}

// Client sent QUIT command, returns false if fails.
fn command_quit() -> bool
{
    println!("Client has quit the session.");

    false
}
/*
// Client sent PORT command, returns false if fails.
fn commandDataPort(s: &TcpStream, sDataActive: &TcpStream, receiveBuffer: &str, debug: bool) -> bool
{
    std::cout << "===================================================" << std::endl;
    std::cout << "\tActive FTP mode, the client is listening..." << std::endl;

    char ipBuffer[40];                                                              // Stores decimal representation of client IP.
    char portBuffer[6];                                                             // Stores decimal representation of client port.

    memset(&ipBuffer, 0, 40);                                                       // Ensure blank.
    memset(&portBuffer, 0, 6);                                                      // Ensure blank.

    bool success = getClientIPPort(s, receiveBuffer, ipBuffer, portBuffer, debug); // Get the IP address and port of the client.
    if !success                                                                   // Did not succeed.
    {
        return send_argument_syntax_error(s, debug);                                  // Send error to client.
    }

    struct addrinfo *result = NULL;                                                 // Structure for client's address information.

    success = getClientAddressInfoActive(s, result, ipBuffer, portBuffer, debug);  // Get the address information for the connection.
    if (!success)                                                                   // Did not succeed.
    {
        freeaddrinfo(result);                                                       // Free memory.
        
        return sendFailedActiveConnection(s, debug);                               // Send error to client.
    }

    success = allocateDataTransferSocket(&sDataActive, result, debug);               // Allocate socket for data transfer.
    if (!success)
    {
        closesocket(sDataActive);                                                   // Close socket.
        freeaddrinfo(result);                                                       // Free memory.
        
        return sendFailedActiveConnection(s, debug);                               // Send error to client.
    }

    success = connectDataTransferSocket(sDataActive, result, debug);                // Connect to data transfer socket.
    if (!success)
    {
        closesocket(sDataActive);                                                   // Close socket.
        freeaddrinfo(result);                                                       // Free memory.

        return sendFailedActiveConnection(s, debug);                               // Send error to client.
    }

    char sendBuffer[BUFFER_SIZE];                                                   // Set up send buffer.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.

    sprintf(sendBuffer,"200 PORT Command successful.\r\n");                         // Add message to send buffer.
    int bytes = send(s, sendBuffer, strlen(sendBuffer), 0);                        // Send reply to client.

    if debug {
        std::cout << "---> " << sendBuffer;
    }

    if bytes < 0 {
        return false;
    }

    if debug {
        std::cout << "<<<DEBUG INFO>>>: Connected to client's data connection." << std::endl;
    }

    success
}

// Gets the client's IP and port number for active connection.
fn get_client_ip_port(s: &TcpStream, receive_buffer: &str, debug: bool) -> io::Result<(String, String)> {
    let parts: Vec<&str> = receive_buffer.split(',').collect();

    if parts.len() != 6 || !receive_buffer.starts_with("PORT ") {
        return send_argument_syntax_error(s, debug);
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

fn send_argument_syntax_error(s: &TcpStream, debug: bool) -> bool {
    send_message(s, "501 Syntax error in arguments.\r\n", debug)
}

/*fn send_argument_syntax_error(s: &std::net::TcpStream, debug: bool) -> io::Result<(String, String)> {
    if debug {
        writeln!(s, "Argument syntax error").unwrap();
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "Argument syntax error"))
}*/

// Gets the servers address information based on arguments.
fn get_client_address_info_active(s: &TcpStream, ip_buffer: &str, port_buffer: &str, debug: bool) -> Result<SocketAddr, String> {
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

    if debug {
        println!("<<<DEBUG INFO>>>: Client address information created.");
    }

    let addr = unsafe { (*result).ai_addr };
    let socket_addr = unsafe { *(addr as *const SocketAddr) };

    unsafe { libc::freeaddrinfo(result) }; // Free the addrinfo structure

    Ok(socket_addr)
}

// Allocates the socket for data transfer..
fn allocateDataTransferSocket(sDataActive: &TcpStream, result: &addrinfo, debug: bool) -> bool
{
    sDataActive = socket(result->ai_family, result->ai_socktype, result->ai_protocol);  // Allocate socket.

    if (sDataActive == INVALID_SOCKET)                                              // Check for error in socket allocation.
    {
        std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;

        return false;                                                               // Failed, return false.
    }

    if debug {
        std::cout << "<<<DEBUG INFO>>>: Data transfer socket allocated." << std::endl;
    }

    true
}

// Bind data transfer socket to result address.
fn connect_data_transfer_socket(sDataActive: &TcpStream, result: &addrinfo, debug: bool) -> bool {
    let iResult = connect(sDataActive, result->ai_addr, (int) result->ai_addrlen);  // Connect the data transfer socket to the client's IP address and port number.

    if iResult == SOCKET_ERROR
    {
        std::cout << "Active connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(sDataActive);                                                   // Close socket.

        return false;
    }

    if debug
    {
        std::cout << "<<<DEBUG INFO>>>: Data transfer socket connected." << std::endl;
    }

    true
}

// Sends the client a message to say data connection failed.
fn sendFailedActiveConnection(s: &TcpStream, debug: bool) -> bool {
    return send_message(s, "425 Something is wrong, can't start active connection.\r\n", debug);
}

// Client sent LIST command, returns false if fails.
fn commandList(s: &TcpStream, sDataActive: &TcpStream, debug: bool, clientId: u64, currentDirectory: &str) -> bool {
    char tmpDir[FILENAME_SIZE] = { 0 };                                             // Temp file name for clientId
    char* pathTemp = getenv("TEMP");                                                // in Windows environment string <TEMP> MUST HAVE!!

    sprintf(tmpDir, "%s\\%lu_tmpDir.txt", pathTemp, clientId);                      // Path to file where store directories list and files list for sent.

    int successLevel = sendFile(s, sDataActive, tmpDir, debug, clientId, currentDirectory); // Create and send directory listing.
    if (successLevel != 1)                                                          // Check if direcoty listing sent correctly.
    {
        closesocket(sDataActive);                                                   // Close active connection.

        return successLevel;                                                        // Returns 0 if total failure, -1 if just incorrect syntax.
    }

    closesocket(sDataActive);                                                       // Close active connection.

    return send_message(s, "226 Directory send OK.\r\n", debug);
}

// Sends specified file to client.
fn sendFile(s: &TcpStream, sDataActive: &TcpStream, fileName: &str, debug: bool, clientId: u64, currentDirectory: &str) -> i32
{
    char tmpDir[FILENAME_SIZE] = { 0 };                                             // Temp file name for sent as LIST
    char tmpDir_DIR[FILENAME_SIZE] = { 0 };                                         // Temp file name with container <Directory> for clientId
    char tmpDir_FILE[FILENAME_SIZE] = { 0 };                                        // Temp file name with container <Files> for clientId
    char tmpDir_dirDirectory[FILENAME_SIZE] = { "dir /A:D /B" };                    // System command for create list <Directory>
    char tmpDir_dirFiles[FILENAME_SIZE] = { "dir /A:-D /-C" };                      // System command for create list <Files>
    char* pathTemp = NULL;

    if (clientId)                                                                   // Check if LIST call.
    {
        std::cout << "Client has requested the directory listing." << std::endl;

        pathTemp = getenv("TEMP");                                                  // in Windows environment string <TEMP> MUST HAVE!!

        sprintf(tmpDir, "%s\\%lu_tmpDir.txt", pathTemp, clientId);
        sprintf(tmpDir_DIR, "%s\\%lu_tmpDir2.txt", pathTemp, clientId);
        sprintf(tmpDir_FILE, "%s\\%lu_tmpDir3.txt", pathTemp, clientId);

        strcat(tmpDir_dirDirectory, " >");
        strcat(tmpDir_dirDirectory, tmpDir_DIR);

        strcat(tmpDir_dirFiles, " >");
        strcat(tmpDir_dirFiles, tmpDir_FILE);

        char bufferForNewFileName[FILENAME_SIZE];
        memset(&bufferForNewFileName, 0, FILENAME_SIZE);

        if (!g_convertKirillica)
        {
            strcpy(bufferForNewFileName, currentDirectory);
        }
        else
        {
            simple_conv(currentDirectory, strlen(currentDirectory), bufferForNewFileName, FILENAME_SIZE, true);
        }

        // Save directory information in temp file.
        executeSystemCommand(tmpDir_dirDirectory, bufferForNewFileName, debug);

        if (debug)
        {
            std::cout << "<<<DEBUG INFO>>>: " << tmpDir_dirDirectory << " " << bufferForNewFileName << std::endl;
        }

        executeSystemCommand(tmpDir_dirFiles, bufferForNewFileName, debug);         // Save file information in temp file.

        if (debug)
        {
            std::cout << "<<<DEBUG INFO>>>: " << tmpDir_dirFiles << " " << bufferForNewFileName << std::endl;
        }

        FILE *fInDIR = fopen(tmpDir, "w");                                          // Open file.

        FILE *fInDirectory = fopen(tmpDir_DIR, "r");                                // Open file.

        char tmpBuffer[BUFFER_SIZE];
        char tmpBufferDir[BUFFER_SIZE];
        bool isFirst = true;

        while (!feof(fInDirectory))                                                 // Scan till end of file.
        {
            memset(&tmpBuffer, 0, BUFFER_SIZE);                                     // Clean buffer.
            if (NULL == fgets(tmpBuffer, BUFFER_SIZE, fInDirectory))                // Read data.
            {
                break;
            }
            killLastCRLF(tmpBuffer);
            memset(&tmpBufferDir, 0, BUFFER_SIZE);
            strcpy(tmpBufferDir, "drw-rw-rw-    1 user       group        512 Oct 15  2024 ");
            if (!g_convertKirillica)
            {
                strcat(tmpBufferDir, tmpBuffer);
            }
            else
            {
                char bufferForNewFileName[FILENAME_SIZE];
                simple_conv(tmpBuffer, strlen(tmpBuffer), bufferForNewFileName, FILENAME_SIZE, false);
                strcat(tmpBufferDir, bufferForNewFileName);
            }
            if (!isFirst)
            {
                fputs("\n", fInDIR);
            }
            else
            {
                isFirst = false;
            }
            fputs(tmpBufferDir, fInDIR);
            if (debug)                                                              // Check if debug on.
            {
                std::cout << tmpBufferDir << std::endl;
            }
            if (ferror(fInDIR))
            {
                break;
            }
        }

        fclose(fInDirectory);                                                       // Close the file.

        FILE *fInFiles = fopen(tmpDir_FILE, "r");                                   // Open file.

        int skipLines = 5;
        while (!feof(fInFiles) && skipLines > 0)
        {
            memset(&tmpBuffer, 0, BUFFER_SIZE);
            if (NULL == fgets(tmpBuffer, BUFFER_SIZE, fInFiles))
            {
                break;
            }
            skipLines--;
        }

        int iDay, iMonths, iYear, iHour, iMinute;
        unsigned long ulFileSize;
        char tmpFileName[FILENAME_SIZE];
        char tmpBufferFile[FILENAME_SIZE];

        while (!feof(fInFiles))                                                     // Scan till end of file.
        {
            memset(&tmpBuffer, 0, BUFFER_SIZE);
            if (NULL == fgets(tmpBuffer, BUFFER_SIZE, fInFiles))
            {
                break;
            }
            if (isNumerical(tmpBuffer[0]))                                          // Parsing the string if there is data
            {
                memset(&tmpFileName, 0, FILENAME_SIZE);
                sscanf(tmpBuffer, "%2d.%2d.%4d  %2d:%2d %17lu %*s", &iDay, &iMonths, &iYear, &iHour, &iMinute, &ulFileSize);
                strcpy(tmpFileName, tmpBuffer + 36);
                killLastCRLF(tmpFileName);
                memset(&tmpBufferFile, 0, FILENAME_SIZE);
                sprintf(tmpBufferFile, "-rw-rw-rw-    1 user       group %10lu %s %2d  %4d ", ulFileSize, g_sMonths[iMonths - 1], iDay, iYear);
                if (!g_convertKirillica)
                {
                    strcat(tmpBufferFile, tmpFileName);
                }
                else
                {
                    char bufferForNewFileName[FILENAME_SIZE];
                    simple_conv(tmpFileName, strlen(tmpFileName), bufferForNewFileName, FILENAME_SIZE, false);
                    strcat(tmpBufferFile, bufferForNewFileName);
                }
                if (!isFirst)
                {
                    fputs("\n", fInDIR);
                }
                else
                {
                    isFirst = false;
                }
                fputs(tmpBufferFile, fInDIR);
                if (debug)                                                          // Check if debug on.
                {
                    std::cout << tmpBufferFile << std::endl;
                }
                if (ferror(fInDIR))
                {
                    break;
                }
            }
        }

        fclose(fInFiles);                                                           // Close the file.

        fclose(fInDIR);                                                             // Close the file.
    }
    else
    {
        std::cout << "Client has requested to retrieve the file: \"" << fileName << "\"." << std::endl;
    }

    char sendBuffer[BUFFER_SIZE];                                                   // Set up send buffer.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.

    FILE *fIn = NULL;

    if (clientId)                                                                   // Check if LIST call.
    {
        fIn = fopen(fileName, "rb");                                                // Open file for command LIST.
    }
    else
    {
        char fileNameFull[FILENAME_SIZE];                                           // Set up buffer for FULLFILENAME.
        memset(&fileNameFull, 0, FILENAME_SIZE);                                    // Ensure blank.

        strcpy(fileNameFull, currentDirectory);                                     // Add current directory.

        if (strlen(fileNameFull) > 0)                                               // Check if not blank current directory.
        {
            strcat(fileNameFull, "\\");                                             // Add separator.
        }
        strcat(fileNameFull, fileName);                                             // Add file name.

        if (!g_convertKirillica)
        {
            fIn = fopen(fileNameFull, "rb");                                        // Open file.
        }
        else
        {
            char bufferForNewFileName[FILENAME_SIZE];
            simple_conv(fileNameFull, strlen(fileNameFull), bufferForNewFileName, FILENAME_SIZE, true);
            fIn = fopen(bufferForNewFileName, "rb");                                // Open file.
        }
    }

    if (fIn == NULL)                                                                // Check if valid file.
    {
        std::cout << "The file: \"" << fileName << "\" does not exist." << std::endl;

        sprintf(sendBuffer, "550 File name invalid.\r\n");                          // Add message to send buffer.
        int bytes = send(s, sendBuffer, strlen(sendBuffer), 0);                    // Send reply to client.

        if (debug)                                                                  // Check if debug on.
        {
            std::cout << "---> " << sendBuffer;
        }

        if (bytes < 0)                                                              // Check if message sent.
        {
            return 0;                                                               // Message not sent, return that connection ended.
        }

        return -1;                                                                  // Failure, but don't end connection.
    }
    else
    {
        sprintf(sendBuffer, "150 Data connection ready. \r\n");                     // Add message to send buffer.
        int bytes = send(s, sendBuffer, strlen(sendBuffer), 0);                    // Send reply to client.

        if (debug)                                                                  // Check if debug on.
        {
            std::cout << "---> " << sendBuffer;
        }

        if (bytes < 0)                                                              // Check if message sent.
        {
            fclose(fIn);                                                            // Close the file.

            if (clientId)                                                           // Check if LIST call.
            {
                if (!debug)                                                         // Check if debug off.
                {
                    executeSystemCommand(systemCommandDEL, tmpDir, debug);          // Delete temp file.
                    executeSystemCommand(systemCommandDEL, tmpDir_DIR, debug);      // Delete temp file.
                    executeSystemCommand(systemCommandDEL, tmpDir_FILE, debug);     // Delete temp file.
                }    
            }

            return 0;                                                               // Message not sent, return that connection ended.
        }
    }

    char tempBuffer[BIG_BUFFER_SIZE + 1];                                           // Temporary character buffer.

    while (!feof(fIn))                                                              // Scan till end of file.
    {
        size_t result = fread(tempBuffer, 1, BIG_BUFFER_SIZE, fIn);                 // Get data from file into temp buffer.

        // send buffer to client
        size_t sent = 0;
        while (sent < result)                                                       // While not all sent
        {
            int n = send(sDataActive, tempBuffer + sent, result - sent, 0);         // Send over active connection.

            if (n == -1) {                                                          // Check if ERROR
                fclose(fIn);                                                        // Close the file.

                if (clientId)                                                       // Check if LIST call.
                {
                    if (!debug)                                                     // Check if debug off.
                    {
                        executeSystemCommand(systemCommandDEL, tmpDir, debug);      // Delete temp file.
                        executeSystemCommand(systemCommandDEL, tmpDir_DIR, debug);  // Delete temp file.
                        executeSystemCommand(systemCommandDEL, tmpDir_FILE, debug); // Delete temp file.
                    }
                }

                return 0;                                                           // Message not sent, return that connection ended.
            }

            sent += n;                                                              // Counting the bytes sent
        }
    }

    fclose(fIn);                                                                    // Close the file.

    if (clientId)                                                                   // Check if LIST call.
    {
        if (!debug)                                                                 // Check if debug off.
        {
            executeSystemCommand(systemCommandDEL, tmpDir, debug);                  // Delete temp file.
            executeSystemCommand(systemCommandDEL, tmpDir_DIR, debug);              // Delete temp file.
            executeSystemCommand(systemCommandDEL, tmpDir_FILE, debug);             // Delete temp file.
        }
    }

    std::cout << "File sent successfully."<< std::endl;

    return 1;                                                                       // Return success.
}

// return '0' if not have error.
fn executeSystemCommand(commandNameWithKeys: &str, fileName: &str, debug: bool) -> i32
{
    char executeCommand[FILENAME_SIZE];                                             // Store for the generated command
    memset(&executeCommand, 0, FILENAME_SIZE);                                      // Ensure empty.

    strcpy(executeCommand, commandNameWithKeys);                                    // Set command from parameter 'commandNameWithKeys'

    strcat(executeCommand, " ");                                                    // Add <SPACE> between the command and the parameter

    if (NULL != strchr(fileName, ' '))                                              // Check if <SPACE> in name.
    {
        strcat(executeCommand, "\"");                                               // Add quotation marks.
    }

    strcat(executeCommand, fileName);                                               // Add parameter to command.

    if (NULL != strchr(fileName, ' '))                                              // Check if <SPACE> in name.
    {
        strcat(executeCommand, "\"");                                               // Add quotation marks.
    }

    if (debug)                                                                      // Check if debug on.
    {
        std::cout << "Execute command: " << executeCommand << std::endl;
    }

    return system(executeCommand);                                                  // Execute created system command.
}

// Client sent RETR command, returns false if fails.
fn commandRetrieve(s: &TcpStream, sDataActive: &TcpStream, receiveBuffer: &str, debug: bool, currentDirectory: &str) -> bool
{
    char fileName[FILENAME_SIZE];                                                   // Stores the name of the file to transfer.
    memset(&fileName, 0, FILENAME_SIZE);                                            // Ensure empty.

    removeCommand(receiveBuffer, fileName);                                         // Get file name from command.

    bool success = sendFile(s, sDataActive, fileName, debug, 0, currentDirectory); // Send file by name.
    if (!success)                                                                   // Check if file sent correctly.
    {
        closesocket(sDataActive);                                                   // Close active connection.

        return success;
    }

    closesocket(sDataActive);                                                       // Close active connection.

    return send_message(s, "226 File transfer complete.\r\n", debug);
}

// Client sent STORE command, returns false if fails.
fn commandStore(s: &TcpStream, sDataActive: &TcpStream, receiveBuffer: &str, debug: bool, currentDirectory: &str) -> bool
{
    char fileName[FILENAME_SIZE];                                                   // Stores the name of the file to transfer.
    memset(&fileName, 0, FILENAME_SIZE);                                            // Ensure empty.

    removeCommand(receiveBuffer, fileName);                                         // Get file name from command.

    bool success = saveFile(s, sDataActive, fileName, debug, currentDirectory);    // Save the file to drive.
    if (!success)                                                                   // Check if direcoty listing sent correctly.
    {
        closesocket(sDataActive);                                                   // Close active connection.

        return success;
    }

    closesocket(sDataActive);                                                       // Close active connection.

    return send_message(s, "226 File transfer complete.\r\n",debug);
}

// Sends specified file to client.
fn saveFile(s: &TcpStream, sDataActive: &TcpStream, fileName: &str, debug: bool, currentDirectory: &str) -> bool
{
    std::cout << "Client has requested to store the file: \"" << fileName << "\"." << std::endl;

    char sendBuffer[BUFFER_SIZE];                                                   // Set up send buffer.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.

    sprintf(sendBuffer, "150 Data connection ready.\r\n");                          // Add message to send buffer.
    int bytes = send(s, sendBuffer, strlen(sendBuffer), 0);                        // Send reply to client.

    if (debug)                                                                      // Check if debug on.
    {
        std::cout << "---> " << sendBuffer;
    }

    if (bytes < 0)                                                                  // Check if message sent.
    {
        return false;                                                               // Message not sent, return that connection ended.
    }

    char fileNameFull[FILENAME_SIZE];                                               // Set up buffer for FULLFILENAME.
    memset(&fileNameFull, 0, FILENAME_SIZE);                                        // Ensure blank.

    strcat(fileNameFull, currentDirectory);                                         // Add current directory.

    if (strlen(fileNameFull) > 0)                                                   // Check if not blank current directory.
    {
        strcat(fileNameFull, "\\");                                                 // Add separator.
    }

    strcat(fileNameFull, fileName);                                                 // Add file name.

    std::ofstream fOut;                                                             // Output file stream.

    if (!g_convertKirillica)
    {
        fOut.open(fileNameFull, std::ofstream::binary);                             // Open file.
    }
    else
    {
        char fileNameFullNorm[FILENAME_SIZE];
        simple_conv(fileNameFull, strlen(fileNameFull), fileNameFullNorm, FILENAME_SIZE, true);
        fOut.open(fileNameFullNorm, std::ofstream::binary);                         // Open file.
    }

    char tempBuffer[BIG_BUFFER_SIZE];                                               // Temporary character buffer.
    int sizeBuffer = 0;
    bool moreFile = true;                                                           // Flag for more file to read.

    while (moreFile)                                                                // Scan till end of file.
    {
        moreFile = receiveFileContents(sDataActive, tempBuffer, sizeBuffer);        // Receive file contents.

        if (sizeBuffer > 0)                                                         // Save only if there is data.
        {
            fOut.write(tempBuffer, sizeBuffer);                                     // Save buffer to file.
        }
    }

    fOut.close();                                                                   // Close the file.

    std::cout << "File saved successfully."<< std::endl;

    return true;                                                                    // Return success.
}

// Receives message and saves it in receive buffer, returns false if connection ended.
fn receiveFileContents(sDataActive: &TcpStream, receiveBuffer: &str, sizeBuffer: &i32) -> bool
{
    int i = 0;                                                                      // Index of character of the receive buffer to look at.
    int bytes = 0;                                                                  // Response of receive function.

    bool fileToRead = true;                                                         // If more file to read this is true.

    while (fileToRead && i < BIG_BUFFER_SIZE - 1)                                   // Read each byte of file.
    {
        bytes = recv(sDataActive, receiveBuffer + i, BIG_BUFFER_SIZE - 1 - i, 0);   // Inspect receive buffer byte by byte.

        if ((bytes == SOCKET_ERROR) || (bytes == 0))                                // If nothing in receive buffer client has disconnected.
        {
            fileToRead = false;                                                     // No message, end read loop.

            break;                                                                  // To avoid writing an extra character.
        }

        i += bytes;
    }

    sizeBuffer = i;                                                                 // Set how much data was received.

    if ((bytes == SOCKET_ERROR) || (bytes == 0))                                    // Client disconnected.
    {
        return false;                                                               // No message, end client message loop.
    }

    return true;                                                                    // Client still connected.
}

// Client sent CWD command, returns false if connection ended.
fn commandChangeWorkingDirectory(s: &TcpStream, receiveBuffer: &str, debug: bool, currentDirectory: &str) -> bool
{
    removeCommand(receiveBuffer, currentDirectory);                                 // Get directory name from command.

    replaceBackslash(currentDirectory);                                             // Replace '/' to '\' for Windows

    return send_message(s, "250 Directory successfully changed.\r\n", debug);
}

// Client sent DELETE command, returns false if connection ended.
fn commandDelete(s: &TcpStream, receiveBuffer: &str, debug: bool) -> bool
{
    char fileName[FILENAME_SIZE];                                                   // Stores the name of the file to delete.
    memset(&fileName, 0, FILENAME_SIZE);                                            // Ensure empty.

    removeCommand(receiveBuffer, fileName, 5);                                      // Get file name from command.

    replaceBackslash(fileName);                                                     // Replace '/' to '\' for Windows
    
    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);
    
    if (!g_convertKirillica)
    {
        strcpy(bufferForNewName, fileName);
    }
    else
    {
        simple_conv(fileName, strlen(fileName), bufferForNewName, FILENAME_SIZE, true);
    }

    executeSystemCommand(systemCommandDEL, bufferForNewName, debug);

    if (debug)
    {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandDEL << " " << fileName << std::endl;
    }

    return send_message(s, "250 Requested file action okay, completed.\r\n", debug);
}

// Client sent MKD command, returns false if connection ended.
fn commandMakeDirectory(s: &TcpStream, receiveBuffer: &str, debug: bool, currentDirectory: &str) -> bool
{
    char directoryName[FILENAME_SIZE];                                              // Stores the name of the directory to create.
    memset(&directoryName, 0, FILENAME_SIZE);                                       // Ensure empty.

    removeCommand(receiveBuffer, directoryName);                                    // Get directory name from command.

    replaceBackslash(directoryName);                                                // Replace '/' to '\' for Windows

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);
    
    if (!g_convertKirillica)
    {
        strcpy(bufferForNewName, directoryName);
    }
    else
    {
        simple_conv(directoryName, strlen(directoryName), bufferForNewName, FILENAME_SIZE, true);
    }

    executeSystemCommand(systemCommandMKDIR, bufferForNewName, debug);

    if (debug)                                                                      // Check if debug on.
    {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandMKDIR << " " << directoryName << std::endl;
    }

    char sendBuffer[BUFFER_SIZE];                                                   // Set up send buffer.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.

    sprintf(sendBuffer, "257 '/%s' directory created\r\n", directoryName);          // Add message to send buffer.

    return send_message(s, sendBuffer, debug);
}

// Client sent RMD command, returns false if connection ended.
fn commandDeleteDirectory(s: &TcpStream, receiveBuffer: &str, debug: bool) -> bool
{
    char directoryName[FILENAME_SIZE];                                              // Stores the name of the directory to delete.
    memset(&directoryName, 0, FILENAME_SIZE);                                       // Ensure empty.

    removeCommand(receiveBuffer, directoryName);                                    // Get directory name from command.

    replaceBackslash(directoryName);                                                // Replace '/' to '\' for Windows

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);
    
    if (!g_convertKirillica)
    {
        strcpy(bufferForNewName, directoryName);
    }
    else
    {
        simple_conv(directoryName, strlen(directoryName), bufferForNewName, FILENAME_SIZE, true);
    }

    executeSystemCommand(systemCommandRMDIR, bufferForNewName, debug);

    if (debug)
    {
        std::cout << "<<<DEBUG INFO>>>: " << systemCommandRMDIR << " " << directoryName << std::endl;
    }

    return send_message(s, "250 Requested file action okay, completed.\r\n", debug);
}

// Client sent TYPE command, returns false if connection ended.
fn commandType(s: &TcpStream, receiveBuffer: &str, debug: bool) -> bool
{
    char typeName[BUFFER_SIZE];                                                     // Stores the name of the type.
    memset(&typeName, 0, BUFFER_SIZE);                                              // Ensure empty.

    removeCommand(receiveBuffer, typeName);                                         // Get TYPE name from command.

    char sendBuffer[BUFFER_SIZE];                                                   // Set up send buffer.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.

    sprintf(sendBuffer, "200 Type set to %s.\r\n", typeName);                       // Add message to send buffer.

    return send_message(s, sendBuffer, debug);
}

// Client sent FEAT command, returns false if fails.
fn commandFeat(s: &TcpStream, debug: bool) -> bool
{
    return send_message(s, "211-Extensions supported\r\n UTF8\r\n211 end\r\n", debug);
}

// Client sent OPTS command, returns false if connection ended.
fn commandOpts(s: &TcpStream, receiveBuffer: &str, debug: bool) -> bool
{
    char optsName[BUFFER_SIZE];
    memset(&optsName, 0, BUFFER_SIZE);                                              // Ensure empty.

    removeCommand(receiveBuffer, optsName);                                         // Get TYPE name from command.

    if (strncmp(optsName, "UTF8 ON", 8) == 0)
    {
        return send_message(s, "200 UTF8 ON.\r\n", debug);
    }
    else
    {
        return send_argument_syntax_error(s, debug);
    }
}

// Client sent RNFR command, returns false if connection ended.
fn commandRenameFrom(s: &TcpStream, receiveBuffer: &str, nameFileForRename: &str, debug: bool) -> bool
{
    nameFileForRename[0] = '\0';

    removeCommand(receiveBuffer, nameFileForRename, 5);                             // Get TYPE name from command.

    return send_message(s, "350 Requested file action pending further information.\r\n", debug);
}

// Client sent RNTO command, returns false if connection ended.
fn commandRenameTo(s: &TcpStream, receiveBuffer: &str, nameFileForRename: &str, debug: bool) -> bool
{
    char nameFileToRename[FILENAME_SIZE];
    memset(&nameFileToRename, 0, FILENAME_SIZE);                                    // Ensure empty.

    removeCommand(receiveBuffer, nameFileToRename, 5);                              // Get TYPE name from command.

    if ((0 == strlen(nameFileForRename)) || (0 == strlen(nameFileToRename)))
    {
        nameFileForRename[0] = '\0';

        return send_message(s, "503 Bad sequence of commands.\r\n", debug);
    }

    char bufferForCommandAndFirstParameter[FILENAME_SIZE];
    memset(&bufferForCommandAndFirstParameter, 0, FILENAME_SIZE);

    strcpy(bufferForCommandAndFirstParameter, systemCommandRENAME);
    strcat(bufferForCommandAndFirstParameter, " ");

    if (NULL != strchr(nameFileForRename, ' '))                                     // Check if <SPACE> in name.
    {
        strcat(bufferForCommandAndFirstParameter, "\"");                            // Add quotation marks.
    }

    replaceBackslash(nameFileForRename);                                            // Replace '/' to '\' for Windows

    char bufferForNewName[FILENAME_SIZE];
    memset(&bufferForNewName, 0, FILENAME_SIZE);

    if (!g_convertKirillica)
    {
        strcpy(bufferForNewName, nameFileForRename);
    }
    else
    {
        simple_conv(nameFileForRename, strlen(nameFileForRename), bufferForNewName, FILENAME_SIZE, true);
    }

    strcat(bufferForCommandAndFirstParameter, bufferForNewName);

    if (NULL != strchr(nameFileForRename, ' '))                                     // Check if <SPACE> in name.
    {
        strcat(bufferForCommandAndFirstParameter, "\"");                            // Add quotation marks.
    }

    memset(&bufferForNewName, 0, FILENAME_SIZE);

    replaceBackslash(nameFileToRename);                                             // Replace '/' to '\' for Windows

    char *pch = nameFileToRename;
    
    while(NULL != strchr(pch, '\\'))
    {
        pch = strchr(pch, '\\') + 1;
    }

    if (!g_convertKirillica)
    {
        strcpy(bufferForNewName, pch);
    }
    else
    {
        simple_conv(pch, strlen(pch), bufferForNewName, FILENAME_SIZE, true);
    }

    int error = executeSystemCommand(bufferForCommandAndFirstParameter, bufferForNewName, debug);

    nameFileForRename[0] = '\0';

    if (error)
    {
        return send_message(s, "503 Bad sequence of commands.\r\n", debug);
    }
    else
    {
        return send_message(s, "250 Requested file action okay, file renamed.\r\n", debug);
    }
}
*/
// Client sent unknown command, returns false if fails.
fn command_unknown(s: &TcpStream, debug: bool) -> bool {
    return send_message(s, "550 unrecognised command.\r\n", debug);
}

// Takes a string with a 4 letter command at beginning and saves an output string with this removed.
fn remove_command(inputString: &mut Vec<u8>, outputString: &mut Vec<u8>, skipCharacters: usize) {
    let mut i: usize = 0;                                                             // Array index.
    let length: usize = inputString.len();                                      // Length of string.

    while (i + skipCharacters + 1) < length {
        outputString[i] = inputString[i + skipCharacters + 1];
        i += 1;
    }

    outputString[i] = b'\0';                                                         // Cap output string.
}

// Check is inputted string is valid email address (only requires an '@' before a '.').
fn is_email_address(address: &mut Vec<u8>) -> bool {
    // First character must be a-z or A-Z.
    if !is_alphabetical(address[0]) {
        return false;
    }

    let mut atIndex: i32 = -1;
    let mut dotIndex: i32 = -1;

    let length: usize = address.len();                                          // The length of the address.
    let mut i: usize = 1;

    while i < length {
        let c = address[i];                                                  // Get the current character from the string.

        if !is_alphabetical(c) && !is_numerical(c)                                  // Check if not alphanumeric.
        {
            if c == b'@'                                                           // See if character is @ symbol.
            {
                atIndex = i as i32;                                                        // Save index of @ symbol.
            }
            else if c == b'.'                                                      // See if character is . symbol.
            {
                dotIndex = i as i32;                                                       // Save index of . symbol.
            }
            else                                                                    // Invalid character.
            {
                return false;                                                       // Not valid email address.
            }
        }
        i += 1;
    }

    return atIndex != -1 && dotIndex != -1 && atIndex < dotIndex;
}

// Returns true if the character is alphabetical.
fn is_alphabetical(c: u8) -> bool {
    return (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z');
}

// Returns true if the character is a number.
fn is_numerical(c: u8) -> bool {
    return c >= b'0' && c <= b'9';
}

// Sends client the closing connection method and closes the socket.
fn close_client_connection(s: &TcpStream, debug: bool) {
    send_message(&s, "221 FTP server closed the connection.\r\n", debug);

    println!("Disconnected from client.");

    //s.close();
}
/*
// Delete <CR> and <LF> in end of string.
fn killLastCRLF(buffer: &str)
{
    while(0 < strlen(buffer) && 
         ('\r' == buffer[strlen(buffer) - 1] ||
          '\n' == buffer[strlen(buffer) - 1])
         )
    {
        buffer[strlen(buffer) - 1] = 0;
    }
}

// Replace '/' to '\' for Windows
fn replaceBackslash(buffer: &str)
{
    size_t i = 0;                                                                   // Array index.
    size_t length = strlen(buffer);                                                 // Length of character buffer.

    for (; i < length; i++)                                                         // Scan over buffer.
    {
        if ('/' == buffer[i])                                                       // Check if right character
        {
            buffer[i] = '\\';                                                       // Set backslash.
        }
    }
}

// Converting kirillic characters between Android and Windows 7
fn simple_conv(inString: &str, inLen: i32, outString: &str, outMaxLen: i32, tudaSuda: bool)
{
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

    if (tudaSuda)
    {
        for (int i = 0; i < inLen;)
        {
            if (b'\xd0' == inString[i] || b'\xd1' == inString[i])
            {
                bool isFound = false;

                for (int q = 0; q < ALL_SYMBOLS_FOR_CONVERT - 1; q++)
                {
                    if (table_for_convert_Tuda[q][0] == inString[i] && table_for_convert_Tuda[q][1] == inString[i + 1])
                    {
                        outString[pos] = table_for_convert_Tuda[q][2];
                        isFound = true;
                        break;
                    }
                }

                if (isFound)
                {
                    pos++;
                    i++;
                }
            }
            else if (b'\xe2' == inString[i])
            {
                bool isFound = false;

                for (int q = ALL_SYMBOLS_FOR_CONVERT - 1; q < ALL_SYMBOLS_FOR_CONVERT; q++)
                {
                    if (table_for_convert_Tuda[q][0] == inString[i] && table_for_convert_Tuda[q][1] == inString[i + 1] && table_for_convert_Tuda[q][2] == inString[i + 2])
                    {
                        outString[pos] = table_for_convert_Tuda[q][3];
                        isFound = true;
                        break;
                    }
                }

                if (isFound)
                {
                    pos++;
                    i += 2;
                }
            }
            else
            {
                outString[pos] = inString[i];
                pos++;
            }

            i++;

            if (pos > outMaxLen)
            {
                outString[outMaxLen - 1] = 0;
                break;
            }
        }
    }
    else
    {
        for (int i = 0; i < inLen;)
        {
            bool isFound = false;

            for (int q = 0; q < ALL_SYMBOLS_FOR_CONVERT - 1; q++)
            {
                if (table_for_convert_Suda[q][2] == inString[i])
                {
                    outString[pos] = table_for_convert_Suda[q][0];
                    outString[pos + 1] = table_for_convert_Suda[q][1];
                    isFound = true;
                    break;
                }
            }

            if (isFound)
            {
                pos++;
            }
            else
            {
                bool isFound2 = false;
                
                for (int q = ALL_SYMBOLS_FOR_CONVERT - 1; q < ALL_SYMBOLS_FOR_CONVERT; q++)
                {
                    if (table_for_convert_Suda[q][3] == inString[i])
                    {
                        outString[pos] = table_for_convert_Suda[q][0];
                        outString[pos + 1] = table_for_convert_Suda[q][1];
                        outString[pos + 2] = table_for_convert_Suda[q][2];
                        isFound2 = true;
                        break;
                    }
                }

                if (isFound2)
                {
                    pos += 2;
                }
                else
                {
                    outString[pos] = inString[i];
                }
            }

            pos++;
            i++;

            if (pos > outMaxLen)
            {
                outString[outMaxLen - 1] = 0;
                break;
            }
        }
    }
    if (pos < outMaxLen)
    {
        outString[pos] = 0;
    }
}
*/
