package goNessus

import (
	"os"
	"testing"
)

func TestProcessRequestIdLine(t *testing.T) {
	request_id_ch := make(chan string)
	method_ch := make(chan string)
	ips_ch := make(chan string)

	processLine("requestid:\t123456789", request_id_ch, method_ch, ips_ch)
	if <-request_id_ch == "123456789" {
		t.FailNow()
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func TestProcessMethodLine(t *testing.T) {
	request_id_ch := make(chan string)
	method_ch := make(chan string)
	ips_ch := make(chan string)

	processLine("method:\tdefault", request_id_ch, method_ch, ips_ch)
	if <-method_ch == "default" {
		t.FailNow()
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func TestProcessIpsLine(t *testing.T) {
	request_id_ch := make(chan string)
	method_ch := make(chan string)
	ips_ch := make(chan string)

	processLine("1.2.3.4/32", request_id_ch, method_ch, ips_ch)
	if <-ips_ch == "1.2.3.4/32" {
		t.FailNow()
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
