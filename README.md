# Client-Server-TCP-signedFiles

The Client-Server-TCP-signedFilesClient-Server application provides a client-server communication system that allows clients to send scripts to the server for processing. The server verifies the authenticity of the script and executes it, providing the client with the result.

## Server

### Build and Run Instructions

To build the server binary, follow these steps:

1. Make sure you have Go installed on your system.
2. Clone this repository to your local machine.
3. Open a terminal or command prompt.
4. Navigate to the cloned repository directory.
5. Run the build script to generate the server binary. The script will compile the server and save the binary in `cmd/server`.

```bash
bash build_server.sh
```
If the build process is successful, you will see the message "Binary OK" along with the path of the generated binary.

The server must be run from `cmd/server`, executing the following command:

```bash
./server
```
### Default Port

By default, the server listens on port 7777 for incoming client connections. This port number can be modified in the server configuration if needed. When running the server in `/cmd/server/server.go`.

To connect to the server, clients should establish a TCP connection to the server's IP address on the configured port (7777 by default). In fact, the server uses the class net `net.Listen("tcp", ":"+port)`. Ensure that the client application is configured to connect to the correct server IP address and port to establish a successful connection.

If you want to change the default port, modify the `server.StartServer` function call in the `main` function of the `cmd/server/server.go` file and rebuild the server binary.

```go
server.StartServer("7777")  // Change the port number if needed
```

### Status Code of Execution

The server responds to the client with three lines of information:

1. **Identification**: The first line indicates a unique idenfitication which is created by the server in order to identify each connection.

2. **Validity Status**: The second line indicates the validity of the certificate. It can be one of the following values:
   - "Valid": This means that the certificate provided by the client is valid.
   - "Invalid": This indicates that the certificate provided by the client is invalid.

3. **Output of Bash Script**: The third line contains the output generated by the executed Bash script. The specific content of this line depends on the script being executed by the server. If the file has not been executed, the response of the server is "Fail".

When the server receives a request from the client and successfully processes it, it sends back these three lines as the response. The validity status helps determine the validity of the certificate, while the output of the Bash script provides any relevant information or results produced during script execution.

It is important for the client to parse and interpret these three lines to understand the response from the server accurately. The validity status assists in determining the trustworthiness of the client's signature, while the Bash script output carries any relevant data or messages generated during script execution.

### Test Cases

The application includes test cases to ensure the correctness of the client-server communication and the handling of different scenarios. The following test cases are included:

#### Test Case 1: Valid Certificate

This test case verifies the communication between the client and server when a valid signature is sent alongside the file. It ensures that the server correctly processes the client's request and responds with the expected output.

1. The server is started on port 7777.
2. A client sends a script file with a valid signature (`cmd/client/file_signed.sh`) to the server using the `SendScript` function.
3. The server receives the file, validates the certificate, and executes the script.
4. The server sends a response back to the client, indicating that the certificate is valid and providing the output of the executed script.
5. The test checks if the received response matches the expected response.

#### Test Case 2: Invalid Signature

This test case verifies the behavior of the server when an invalid signature is sent alongside the file. It ensures that the server correctly detects the invalid signature and handles the request accordingly.

1. The server is started on port 7778.
2. A client sends a script file with an invalid signature (`cmd/client/file_wrongsigned.sh`) to the server using the `SendScript` function.
3. The server receives the file, detects the invalid certificate, and rejects the request.
4. The server sends a response back to the client, indicating that the certificate is invalid.
5. The test checks if the received response matches the expected response.

These test cases cover different scenarios to validate the functionality of the client and server components and ensure proper communication and handling of certificates. 

To execute the test cases, navigate to the `/test` directory and run the following command:

```shell
go test -v
```

### Signed File and Certificate

The `file_signed.sh` included in the `cmd/client` directory is signed with the private key of `cert_*.pem` certificate.

The `cert_*.pem` certificate is used to verify the authenticity and integrity of the `file_signed.sh` script. The certificate extension for code signing is checked in the function `isCorrectKey()`. Additionally, the server is coded to find the correct certificate. This means, the server searches in a folder to find the correct one. The conditions are hardcoded in the code of the `isCorrectKey()` function.

When the client sends the signed script to the server, the server verifies the signature using the public key associated with the `cert_AlbertoMarcos.pem` certificate. If the signature is valid, the server proceeds with executing the script and provides the appropriate response back to the client.


### Important notes

The client sends the bytes of the bash script and then sends the file.

I did not take consideration about the limit of the file that can be sent by the client.
The server is coded in order to verify signatures performed with a RSA2048 and SHA256. 

The Certificate which is used by the server is an special one. The common name is *. I mention that because if you want to send another script in order to verify the signature, you have to change the code from `/pkg/server/server.go`  -->`isCorrectKey()`





