package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

const (
	server = "localhost:7777" // Dirección del servidor

)

func SendScript(filePath string) string {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error:", err)
		return "Error"
	}

	fmt.Println("Ruta actual:", currentDir)

	// Open the file to be sent
	fmt.Println(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err.Error())
		return "Error"
	}
	defer file.Close()

	// Conecta al servidor
	conn, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Println("Error connecting to server:", err.Error())
		return "Error"
	}
	//defer conn.Close()

	// obtaining file info
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("Error getting file information:", err.Error())
		return "Error"
	}

	// get the byte length of the file
	fileSize := fileInfo.Size()
	fileSizeStr := strconv.FormatInt(fileSize, 10)

	//fileName := []byte(lastPart)
	fileName := []byte(fileSizeStr)
	_, err = conn.Write(fileName)
	if err != nil {
		fmt.Println("Error sending file name:", err.Error())
		return "Error"
	}

	// Envía los datos del archivo al servidor
	buffer := make([]byte, 1024)
	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading file:", err.Error())
			}
			break
		}

		_, err = conn.Write(buffer[:bytesRead])
		if err != nil {
			fmt.Println("Error sending file data:", err.Error())
			return "Error"
		}
	}

	fmt.Println("File sent successfully.")
	file.Close()
	// Leer primera respuesta del servidor
	response1 := make([]byte, 1024)
	n, err := conn.Read(response1)
	if err != nil {
		fmt.Println("Error al recibir la primera respuesta:", err.Error())
		os.Exit(1)
	}
	response1 = response1[:n]
	fmt.Println("Respuesta del servidor:", string(response1))
	return string(response1)

}
