package goNessus

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// Builds the JSON object to send to Nessus when creating a scan.
//
// @param name [string] The name of the to be created Nessus Scan
// @param description [string] The description of the scan
// @param policy_id [string] The policy which should be used to create the custom scan
// @param text_targets [string] The IP Addresses which should be scanned
func (nessus *Nessus) BuildCreateScanJson(target_scan_ch chan *TargetScan,
	json_ch chan string, num_of_files int) {

	for i := 0; i < num_of_files; i++ {
		log.Print("[INFO] ", "Creating create scan option object")

		targetScan := <-target_scan_ch

		name := fmt.Sprintf("Scan Request #%s", targetScan.RequestID)
		description := fmt.Sprintf("Scan Request #%s, Method %s", targetScan.RequestID, targetScan.Method)
		text_targets := strings.Join(targetScan.IPs[:], " ")

		var policy_id string
		switch targetScan.Method {
		case "allportswithping":
			policy_id = "52"
		case "allportsnoping":
			policy_id = "53"
		case "atomic":
			policy_id = "54"
		case "pci":
			policy_id = "55"
		default:
			policy_id = "19"
		}

		settings := CreateScanSettings{
			Name:         name,
			Description:  description,
			Folder_id:    "65",
			Scanner_id:   "1",
			Policy_id:    policy_id,
			Text_targets: text_targets,
			File_targets: "",
			Launch:       "ONETIME",
			Enabled:      false,
			Launch_now:   false,
			Emails:       "",
		}
		new_scan := CreateScan{
			Uuid:     "ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40",
			Settings: settings,
		}
		marshalled_scan, err := json.Marshal(new_scan)
		if err != nil {
			log.Print("[ERROR] ", err)
			os.Exit(1)
		}
		json_ch <- string(marshalled_scan)
	}
}

// Creates a new scan on the Nessus server.
//
// @param nessus [Nessus] The Nessus client struct
// @param json_ch [chan string] The channel that we will receive JSON create opts on
func (nessus *Nessus) CreateScan(json_ch chan string, new_scan_ch chan CreateScanResponse, num_of_files int) {

	for i := 0; i < num_of_files; i++ {
		string_chan := make(chan string)
		scan_opts := <-json_ch
		log.Print("[INFO] ", "Creating new scan.")
		go nessus.PerformPostWithArgs("scans", scan_opts, string_chan)

		status, body := <-string_chan, <-string_chan
		switch status {
		case "200 OK":
			if status == "200 OK" {
				log.Print("[INFO] ", "Processing create scan response.")
				jsonSrc := []byte(body)
				var jsonResponse CreateScanResponse
				json.Unmarshal(jsonSrc, &jsonResponse)
				new_scan_ch <- jsonResponse
			}
		default:
			log.Fatal("[FATAL]", "Received an error", status, body)
			panic(body)
			os.Exit(1)
		}
	}
}
