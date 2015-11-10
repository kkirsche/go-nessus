package goNessus

import (
	"fmt"
	"log"
	"os"
)

func (nessus *Nessus) DownloadScan(scan_id string,
	export_scan_ch chan ExportScanResponse, scan_result_ch chan string) {

	scan_file_id := <-export_scan_ch
	log.Print("[INFO] ", fmt.Sprintf("Downloading scan %s with file id %s.", scan_id, scan_file_id))
	url := fmt.Sprintf("scans/%s/export/%d/download", scan_id, scan_file_id.File)
	response_ch := make(chan string, 10)
	nessus.PerformGet(url, response_ch)
	status, csv_body := <-response_ch, <-response_ch
	switch status {
	case "200 OK":
		if status == "200 OK" {
			scan_result_ch <- csv_body
		}
	default:
		log.Fatal("[FATAL]", "Received an error", status, csv_body)
		os.Exit(1)
	}
}
