package nessus

import (
	"encoding/json" //For converting structs to JSON
	"fmt"           // For debugging purposes
	"log"           // For logging
)

func LaunchScan(nessus Nessus, new_scan_ch chan CreateScanResponse,
	scan_id_ch chan int, launched_scan_ch chan LaunchScanResponse) {

	launched_ch := make(chan string)
	scan := <-new_scan_ch
	url := fmt.Sprintf("scans/%d/launch", scan.Scan.ID)

	log.Print("[INFO] ", "Launching scan with URL: ", "https://", nessus.Ip, ":", nessus.Port, "/", url)
	status, body := nessus.performPost(url, launched_ch)
	switch status {
	case "200 OK":
		if status == "200 OK" {
			log.Print("[INFO] ", "Processing launch scan response.")
			jsonSrc := []byte(body)
			var jsonResponse LaunchScanResponse
			json.Unmarshal(jsonSrc, &jsonResponse)
			scan_id_ch <- scan.Scan.ID
			launched_scan_ch <- jsonResponse
		}
	default:
		log.Fatal("[FATAL]", "Received an error", status, body)
		panic(body)
	}
}
