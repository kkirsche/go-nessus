package gonessus

import (
	"encoding/json"                    //For converting structs to JSON
	"fmt"                              // For debugging purposes
	"github.com/mxk/go-sqlite/sqlite3" // SQLite3 Database Communications
	"log"                              // For logging
)

func (nessus *Nessus) AsyncLaunchCreated(new_scan_ch chan CreateScanResponse,
	scan_id_ch chan int, launched_scan_ch chan LaunchScanResponse) {

	launched_ch := make(chan string)
	scan := <-new_scan_ch
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
		log.Fatal("[FATAL]", "Received an error", status, body)
		panic(body)
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
		log.Fatal("[FATAL]", "Received an error", status, body)
		panic(body)
	}
	return 0, LaunchScanResponse{}
}

func (nessus *Nessus) SaveLaunchedScan(database_name string, scan_id_chan chan int, launched_scan_ch chan LaunchScanResponse) {
	log.Print("[INFO] ", "Connecting to SQLite3 database (launched_nessus_scans.db)")
	conn, err := sqlite3.Open(database_name)
	if err != nil {
		log.Fatal("[FATAL]", "Couldn't connect to the database.", err)
	}

	log.Print("[INFO] ", "Creating active_scans table if it doesn't exist.")
	go conn.Exec("CREATE TABLE IF NOT EXISTS active_scans (request_id bigint, method varchar(200), scan_uuid varchar(250), scan_id integer);")

	log.Print("[INFO] ", "Waiting for launched scan...")
	id := <-scan_id_chan
	launched_scan := <-launched_scan_ch

	args := sqlite3.NamedArgs{"$a": "1", "$b": "default", "$c": launched_scan.ScanUUID, "$d": id}
	log.Print("[INFO] ", "Saving the launched scan into SQLite3 database.")
	log.Print("[SQL] ", fmt.Sprintf("INSERT INTO active_scans (request_id, method, scan_uuid, scan_id) VALUES (%s, %s, %s, %d)", "1", "default", launched_scan.ScanUUID, id))
	go conn.Exec("INSERT INTO active_scans (request_id, method, scan_uuid, scan_id) VALUES ($a, $b, $c, $d)", args)
	log.Print("[INFO]", "Launched scan saved! ", "Exiting...")
}
