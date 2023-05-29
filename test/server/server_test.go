package main_test

import (
	"Canonical_ClientServer/pkg/client"
	"Canonical_ClientServer/pkg/server"
	"strings"
	"testing"
	"time"
)

func TestClientServerCommunication_ValidCert(t *testing.T) {

	go server.StartServer("7777")
	time.Sleep(2 * time.Second)

	response := client.SendScript("../../cmd/client/file_signed.sh")

	parts := strings.Split(response, "\n")
	expectedResponseCertificate := "Valid"
	if parts[1] != expectedResponseCertificate {
		t.Errorf("The recieved response (%s) does not match the expected response (%s)\n", parts[1], expectedResponseCertificate)
	}
	expectedResponseBash := "Hola, mundo."

	if string(strings.TrimSpace(parts[2])) != expectedResponseBash {
		t.Errorf("The recieved response (%s) does not match the expected response (%s)\n", parts[2], expectedResponseBash)
	}

}

func TestClientServerCommunication_invValidCert(t *testing.T) {

	go server.StartServer("7778")
	time.Sleep(2 * time.Second)

	response := client.SendScript("../../cmd/client/file_wrongsigned.sh")

	parts := strings.Split(response, "\n")
	expectedResponseCertificate := "Invalid"
	if parts[1] != expectedResponseCertificate {
		t.Errorf("The recieved response (%s) does not match the expected response (%s)\n", parts[1], expectedResponseCertificate)
	}
	expectedResponseBash := "Fail"

	if string(strings.TrimSpace(parts[2])) != expectedResponseBash {
		t.Errorf("The recieved response (%s) does not match the expected response (%s)\n", parts[2], expectedResponseBash)
	}

}
