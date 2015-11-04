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

func (nessus Nessus) Launch(scan_id int) (chan int, chan LaunchScanResponse) {
	new_scan_ch := make(chan CreateScanResponse)
	scan_id_ch := make(chan int)
	launched_scan_ch := make(chan LaunchScanResponse)
	LaunchScan(nessus, new_scan_ch, scan_id_ch, launched_scan_ch)

	return scan_id_ch, launched_scan_ch
}
