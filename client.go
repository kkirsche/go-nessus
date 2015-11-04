package nessus

import (
	"fmt"
)

func (nessus Nessus) MakeClient(host, port, accessKey, secretKey string) Nessus {
	return Nessus{
		Ip:        fmt.Sprintf("%s", host),
		Port:      fmt.Sprintf("%s", port),
		AccessKey: fmt.Sprintf("%s", accessKey),
		SecretKey: fmt.Sprintf("%s", secretKey),
	}
}
