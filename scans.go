package goNessus

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/mxk/go-sqlite/sqlite3" // SQLite3 Database Communications
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

// Builds the JSON object to send to Nessus when creating a scan.
//
// @param name [string] The name of the to be created Nessus Scan
// @param description [string] The description of the scan
// @param policy_id [string] The policy which should be used to create the custom scan
// @param text_targets [string] The IP Addresses which should be scanned
func (nessus *Nessus) AsyncBuildCreateScanJson(target_scan_ch chan *TargetScan,
	json_ch chan string, filename_ch chan string, num_of_files int) {

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
		CheckErr(err)
		json_ch <- string(marshalled_scan)
		filename_ch <- string(targetScan.FileName)
	}
}

// Creates a new scan on the Nessus server.
//
// @param nessus [Nessus] The Nessus client struct
// @param json_ch [chan string] The channel that we will receive JSON create opts on
func (nessus *Nessus) AsyncCreateScan(json_ch chan string, new_scan_ch chan CreateScanResponse, num_of_files int) {

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
		case "401 Authorization required":
			log.Print("[ERROR] ", "Failed to create scan in Nessus. The credentials provided are not authorized to create scans.")
			new_scan_ch <- CreateScanResponse{}
		default:
			log.Panic("[FATAL] ", "Received an error", status, body)
		}
	}
}

func (nessus *Nessus) AsyncLaunchCreated(new_scan_ch chan CreateScanResponse,
	scan_id_ch chan int, launched_scan_ch chan LaunchScanResponse, num_of_files int) {

	emptyCreateScanStruct := CreateScanResponse{}
	for i := 0; i < num_of_files; i++ {
		launched_ch := make(chan string)
		scan := <-new_scan_ch
		if scan != emptyCreateScanStruct {
			url := fmt.Sprintf("scans/%d/launch", scan.Scan.ID)

			log.Print("[INFO] ", "Launching scan with URL: ", "https://", nessus.Ip, ":", nessus.Port, "/", url)
			go nessus.PerformPost(url, launched_ch)
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
				log.Print("[ERROR] ", "Failed to launch scan in Nessus. Received the following status from the server: ", status)
				scan_id_ch <- 0
				launched_scan_ch <- LaunchScanResponse{}
			}
		} else {
			scan_id_ch <- 0
			launched_scan_ch <- LaunchScanResponse{}
		}
	}
}

func (nessus *Nessus) LaunchCreated(scan CreateScanResponse, scan_id int) (int, LaunchScanResponse) {
	url := fmt.Sprintf("scans/%d/launch", scan.Scan.ID)

	log.Print("[INFO] ", "Launching scan with URL: ", "https://", nessus.Ip, ":", nessus.Port, "/", url)
	launched_ch := make(chan string)
	go nessus.PerformPost(url, launched_ch)
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
		log.Panic("[FATAL] ", "Received an error", status, body)
	}
	return 0, LaunchScanResponse{}
}

func (nessus *Nessus) AsyncSaveLaunchedScan(database_name string, scan_id_chan chan int,
	launched_scan_ch chan LaunchScanResponse, filename_ch chan string, fileLocations FileLocations, num_of_files int) {
	message := fmt.Sprintf("Connecting to SQLite3 database (%s)", database_name)
	log.Print("[INFO] ", message)
	conn, err := sql.Open("sqlite3", database_name)
	if err != nil {
		log.Panic("[FATAL] ", "Couldn't connect to the database.", err)
	}
	defer conn.Close()

	log.Print("[INFO] ", "Creating active_scans table if it doesn't exist.")
	go conn.Exec("CREATE TABLE IF NOT EXISTS active_scans (request_id bigint, method varchar(200), scan_uuid varchar(250), scan_id integer);")

	emptyLaunchedStruct := LaunchScanResponse{}
	for i := 0; i < num_of_files; i++ {
		id := <-scan_id_chan
		launched_scan := <-launched_scan_ch

		if id != 0 && launched_scan != emptyLaunchedStruct {
			args := sqlite3.NamedArgs{"$a": "1", "$b": "default", "$c": launched_scan.ScanUUID, "$d": id}
			log.Print("[INFO] ", "Saving the launched scan into SQLite3 database.")
			log.Print("[SQL] ", fmt.Sprintf("INSERT INTO active_scans (request_id, method, scan_uuid, scan_id) VALUES (%s, %s, %s, %d)", "1", "default", launched_scan.ScanUUID, id))
			go conn.Exec("INSERT INTO active_scans (request_id, method, scan_uuid, scan_id) VALUES ($a, $b, $c, $d)", args)
			log.Print("[INFO] ", "Launched scan saved! ")
		}

		filename := <-filename_ch
		log.Print("[INFO] ", "Attempting to remove file %q from temporary directory.", filename)
		file_to_be_removed := fmt.Sprintf("%s/%s", fileLocations.Temp_directory, filename)
		err := os.Remove(file_to_be_removed)
		CheckErr(err)
	}

	log.Print("Exiting...")
}

func (nessus *Nessus) AsyncExportScan(scan_id string, export_scan_ch chan ExportScanResponse) {
	log.Print("[INFO] ", fmt.Sprintf("Attempting to export scan %s.", scan_id))
	url := fmt.Sprintf("scans/%s/export", scan_id)
	opts := "{\"format\":\"csv\"}"
	response_ch := make(chan string, 10)
	nessus.PerformPostWithArgs(url, opts, response_ch)
	status, body := <-response_ch, <-response_ch
	switch status {
	case "200 OK":
		jsonSrc := []byte(body)
		var jsonResponse ExportScanResponse
		json.Unmarshal(jsonSrc, &jsonResponse)
		export_scan_ch <- jsonResponse
	case "404 File not found":
		log.Printf("[INFO] Scan %s was not found. Skipping to the next file.", scan_id)
		export_scan_ch <- ExportScanResponse{File: 0}
	default:
		log.Panic("[FATAL] ", "Received an error", status, body)
	}
}

func IsScanReady(nessus *Nessus, url string) bool {
	response_ch := make(chan string, 10)
	nessus.PerformGet(url, response_ch)
	status, body := <-response_ch, <-response_ch
	switch status {
	case "200 OK":
		jsonSrc := []byte(body)
		var jsonResponse ExportScanStatusResponse
		json.Unmarshal(jsonSrc, &jsonResponse)
		if jsonResponse.Status != "ready" {
			return false
		} else {
			return true
		}
	case "404 File not found":
		return false
	default:
		log.Panic("[FATAL] ", "Received an error", status, body)
	}
	return false
}

func (nessus *Nessus) AsyncWaitForScan(scan_id string, export_scan_ch chan ExportScanResponse,
	file_exported_ch chan ExportScanResponse) {
	exported_scan := <-export_scan_ch
	if exported_scan.File != 0 {
		log.Print("[INFO] ", fmt.Sprintf("Checking export scan status for Scan #%s with file ID %d.", scan_id, exported_scan.File))
		url := fmt.Sprintf("scans/%s/export/%d/status", scan_id, exported_scan.File)
		for !IsScanReady(nessus, url) {
			time.Sleep(1000)
		}
		log.Print("[INFO] ", fmt.Sprintf("Scan #%s with file ID %d is ready to be downloaded.", scan_id, exported_scan.File))
		file_exported_ch <- exported_scan
	} else {
		file_exported_ch <- exported_scan
	}
}

func (nessus *Nessus) AsyncDownloadScan(scan_id string,
	file_exported_ch chan ExportScanResponse, scan_result_ch chan string, scan_id_ch chan string) {

	scan_file_id := <-file_exported_ch
	if scan_file_id.File != 0 {
		log.Print("[INFO] ", fmt.Sprintf("Downloading scan %s with file id %d.", scan_id, scan_file_id.File))
		url := fmt.Sprintf("scans/%s/export/%d/download", scan_id, scan_file_id.File)
		response_ch := make(chan string, 10)
		nessus.PerformGet(url, response_ch)
		status, csv_body := <-response_ch, <-response_ch
		switch status {
		case "200 OK":
			if status == "200 OK" {
				scan_result_ch <- csv_body
				scan_id_ch <- scan_id
			}
		default:
			log.Panic("[FATAL] ", "Received an error", status, csv_body)
		}
	} else {
		scan_result_ch <- ""
	}
}

func (nessus *Nessus) AsyncSaveDownloadedScan(path string, scan_result_ch chan string, scan_id_ch chan string, file_ch chan bool) {
	downloaded_scan := <-scan_result_ch
	if downloaded_scan != "" {
		filename := fmt.Sprintf("Scan%sResults.csv", <-scan_id_ch)
		full_path := fmt.Sprintf("%s/%s", path, filename)
		err := ioutil.WriteFile(full_path, []byte(downloaded_scan), 0644)
		CheckErr(err)
		file_ch <- true
	}
	file_ch <- false
}
