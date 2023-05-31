package server

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	ConnectionID      int
	CertificateStatus string
	OutputBash        string
}

const (
	saveFolder = "./saved_files" // Carpeta donde se guardarán los archivos recibidos
)

func StartServer(port string) {

	// Create a folder if it is not exist
	err := os.MkdirAll(saveFolder, 0777)
	if err != nil {
		fmt.Println("Error creating save folder:", err.Error())
		return
	}

	// Listen for incoming connections on the specified port
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()

	fmt.Println("Server listening on port", port)
	//LOOP OF THE SERVER
	// run loop forever (or until ctrl-c)
	for {

		// Acepta una conexión entrante del cliente
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err.Error())
			continue
		}

		// Assigns a unique identifier to the connection
		connID := time.Now().UnixNano()

		// start a go routine to handle each connection
		go handleClientConnection(conn, int(connID))

	}

}

func handleClientConnection(conn net.Conn, id int) {

	defer conn.Close()
	res := Result{
		ConnectionID:      id,
		CertificateStatus: "Invalid",
		OutputBash:        "Fail",
	}
	// First of all, we recieved the name of the file from the client
	Buffer := make([]byte, 1024)
	_, err := conn.Read(Buffer)
	if err != nil {
		fmt.Println("Error receiving file name:", err.Error())
		return
	}

	fileBytes := strings.TrimRight(string(Buffer), "\x00")

	//Save the file which has been sent by the client. This file is not deleted at the end.
	timestamp := time.Now().Format("20060102150405")
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := strings.Replace(remoteAddr, ":", "_", 1)
	fileNameWithTimestamp := fmt.Sprintf("%s_%s.sh", strings.TrimSuffix(remoteIP, ".sh"), timestamp)
	savePath := filepath.Join(saveFolder, fileNameWithTimestamp)
	file, err := os.Create(savePath)
	if err != nil {
		fmt.Println("Error creating destination file:", err.Error())
		return
	}

	lenBytesFile, err := strconv.Atoi(fileBytes)
	totalBytesRead := 0
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}
	// Read the data from the client and write it
	buffer := make([]byte, 1024)
	for totalBytesRead < lenBytesFile {
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error receiving file data:", err.Error())

			}
			fmt.Println("Error receiving file data:", err.Error())
			break

		}
		totalBytesRead += bytesRead
		_, err = file.Write(buffer[:bytesRead])
		if err != nil {
			fmt.Println("Error writing to file:", err.Error())
			return
		}
	}

	file.Close()

	fmt.Println("File saved:", savePath)
	/////////////////////////////////////////////////////////////////
	// Open the file save in order to handle it
	fileopen, err := os.Open(savePath)
	if err != nil {
		fmt.Println("Error open the file:", err.Error())
		return
	}
	reader := bufio.NewReader(fileopen)

	// Read the signature of the file (first line)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading the first line of the bash:", err.Error())
		return
	}

	bashFileBytes, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("Error reading the file:", err)

	}
	fileopen.Close()
	//Finding correct cert key
	pathCert, err := findCorrectKeyCert("../../cmd/server/certificates")
	if err != nil {
		fmt.Println("Error Finding correct key:", err)
		_, err = reponseToClient(res, conn)
		if err != nil {
			fmt.Println("Error sending data to the client:", err)
		}

	}
	//verifying signature
	valid, err := VerifySignature(pathCert, savePath, line)
	if err != nil {
		fmt.Println("Error verifying the signature:", err)

		_, err = reponseToClient(res, conn)
		if err != nil {
			fmt.Println("Error sending data to the client:", err)
		}

		return
	}
	//validate if the file has been verified or not.
	if valid {
		output := executebash(bashFileBytes)
		res.CertificateStatus = "Valid"
		res.OutputBash = output

	}
	//Sending data to the client
	_, err = reponseToClient(res, conn)
	if err != nil {
		fmt.Println("Error sending data to the client:", err)
	}

}

func reponseToClient(res Result, conn net.Conn) (int, error) {
	stringoutput := (strconv.Itoa(res.ConnectionID) + "\n" + res.CertificateStatus + "\n" + res.OutputBash)

	bytesSent, err := conn.Write([]byte(stringoutput))
	if err != nil {
		fmt.Println("Error sending response to client:", err.Error())
		return bytesSent, err
	}

	fmt.Println("Response sent to client:", stringoutput)
	return bytesSent, err
}

func VerifySignature(certFile, bashFile, signature string) (bool, error) {
	// Load the Certificate
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return false, fmt.Errorf("Error loading certificate: %s", err)
	}

	// Decode Certificate PEM
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return false, fmt.Errorf("Error decoding PEM certificate")
	}

	// Parse Certificate X.509
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("Error parsing the X.509 certificate: %s", err)
	}

	// Decode the base64 signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Error decoding signature in base64:", err)
	}
	// Read the bashfile
	fileBytes, err := os.ReadFile(bashFile)
	if err != nil {
		fmt.Println("Error reading file:", err)

	}

	// Create a byte reader
	reader := bufio.NewReader(bytes.NewReader(fileBytes))

	// Read and discard the first line
	_, err = reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading first line:", err)

	}

	// Read the rest of the file
	bashFileBytes, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("Error reading file:", err)

	}

	// Compute hash SHA-256 of the file
	hash := sha256.Sum256(bashFileBytes)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signatureBytes)
	if err != nil {
		return false, fmt.Errorf("Error verifying signature: %s", err)
	}

	// La firma es válida
	return true, nil

}

func executebash(shBytes []byte) string {

	// Create an file to write the bytes from the bash which has to be executed
	tmpfile, err := os.CreateTemp(saveFolder, "bashtoexecute*.sh")
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return "Fail"
	}
	defer os.Remove(tmpfile.Name()) // delete the temporary file at the end of the function

	_, err = tmpfile.Write(shBytes)
	if err != nil {
		fmt.Println("Error writing to temporary file:", err)
		return "Fail"
	}

	// Configure the permisions
	err = tmpfile.Chmod(0700)
	if err != nil {
		fmt.Println("Error setting execute permissions:", err)
		return "Fail"
	}
	tmpfile.Close()

	// Execute the file .sh using the comand "sh" from the system
	// The output will be outputed using Stdout of the server. No information is sent back to the client
	cmd := exec.Command("sh", tmpfile.Name())

	output, err := cmd.Output()

	if err != nil {
		fmt.Println("Error executing the file:", err)

	}
	return string(output)
}

func findCorrectKeyCert(directory string) (string, error) {
	//fmt.Println("directory", directory)

	var correctPath string

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".pem" {
			return nil
		}

		pemData, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		// Check if the certificate meets our criteria for the correct key

		if isCorrectKey(cert) {
			correctPath = path

			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {

		return correctPath, err
	}

	return correctPath, nil
}

func isCorrectKey(cert *x509.Certificate) bool {
	//Perform different checks
	//
	now := time.Now()
	if (cert.KeyUsage&x509.KeyUsageDigitalSignature) == x509.KeyUsageDigitalSignature &&
		cert.SignatureAlgorithm == x509.SHA256WithRSA &&
		now.After(cert.NotBefore) &&
		now.Before(cert.NotAfter) && (cert.Issuer.CommonName == "Alberto.Marcos") {
		return true
	}
	return false
}
