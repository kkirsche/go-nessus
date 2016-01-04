package goNessus

import (
	"fmt"
)

// Creates a new Nessus client struct which can be used to make Nessus API calls
func MakeClient(host, port, accessKey, secretKey string) *Nessus {
	return &Nessus{
		Ip:        fmt.Sprintf("%s", host),
		Port:      fmt.Sprintf("%s", port),
		AccessKey: fmt.Sprintf("%s", accessKey),
		SecretKey: fmt.Sprintf("%s", secretKey),
	}
}
