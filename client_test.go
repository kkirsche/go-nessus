package goNessus

import (
	"os"
	"testing"
)

func TestMakeClient(t *testing.T) {
	client := MakeClient("localhost", "1234", "TestAccessKey", "TestSecretKey")
	if client.Ip != "localhost" {
		t.FailNow()
	} else {
		os.Exit(0)
	}
}
