package go_nessus

import (
	"encoding/json" //For converting structs to JSON
	"fmt"           // For debugging purposes
	"log"           // For logging
)

func (nessus *Nessus) AsyncLaunchCreated(new_scan_ch chan CreateScanResponse,
	scan_id_ch chan int, launched_scan_ch chan LaunchScanResponse) {

	launched_ch := make(chan string)
	scan := <-new_scan_ch
	url := fmt.Sprintf("scans/%d/launch", scan.Scan.ID)

	log.Print("[INFO] ", "Launching scan with URL: ", "https://", nessus.Ip, ":", nessus.Port, "/", url)
	go nessus.performPost(url, launched_ch)
	status, body := <-launched_ch, <-launched_ch
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

func (nessus *Nessus) LaunchCreated(scan CreateScanResponse, scan_id int) (int, LaunchScanResponse) {
	url := fmt.Sprintf("scans/%d/launch", scan.Scan.ID)

	log.Print("[INFO] ", "Launching scan with URL: ", "https://", nessus.Ip, ":", nessus.Port, "/", url)
	launched_ch := make(chan string)
	go nessus.performPost(url, launched_ch)
	status, body := <-launched_ch, <-launched_ch
	switch status {
	case "200 OK":
		if status == "200 OK" {
			log.Print("[INFO] ", "Processing launch scan response.")
			jsonSrc := []byte(body)
			var jsonResponse LaunchScanResponse
			json.Unmarshal(jsonSrc, &jsonResponse)
			return scan.Scan.ID, jsonResponse
		}
	default:
		log.Fatal("[FATAL]", "Received an error", status, body)
		panic(body)
	}
	return 0, LaunchScanResponse{}
}
