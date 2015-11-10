package goNessus

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func (nessus *Nessus) ExportScan(scan_id string, export_scan_ch chan ExportScanResponse) {
	log.Print("[INFO] ", fmt.Sprintf("Exporting scan %s.", scan_id))
	url := fmt.Sprintf("scans/%s/export", scan_id)
	opts := "{\"format\":\"csv\"}"
	response_ch := make(chan string, 10)
	nessus.PerformPostWithArgs(url, opts, response_ch)
	status, body := <-response_ch, <-response_ch
	switch status {
	case "200 OK":
		if status == "200 OK" {
			log.Print("[INFO] ", "Processing export scan response.")
			jsonSrc := []byte(body)
			var jsonResponse ExportScanResponse
			json.Unmarshal(jsonSrc, &jsonResponse)
			export_scan_ch <- jsonResponse
		}
	default:
		log.Fatal("[FATAL]", "Received an error", status, body)
		os.Exit(1)
	}
}
