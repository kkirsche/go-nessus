package goNessus

import (
	"database/sql"                                                                           // For using the SQLite3 Library
	"fmt"                                                                                    // For debugging purposes
	_ "github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/mxk/go-sqlite/sqlite3" // SQLite3 Database Communications
	"log"                                                                                    // For logging
	"os"                                                                                     // For retrieving the PID
	"runtime"                                                                                // For retrieving the current OS runtime (e.g. Linux, Windows or Darwin)
)

func ConstructFileLocations() FileLocations {
	if runtime.GOOS == "linux" {
		fileLocations := FileLocations{Base_directory: "/opt/scanner"}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Archive_directory = fmt.Sprintf("%s/targets/archive", fileLocations.Base_directory)
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	} else if runtime.GOOS == "darwin" {
		// Use PWD since don't really know where to put this type of thing
		pwd, err := os.Getwd()
		CheckErr(err)

		fileLocations := FileLocations{Base_directory: pwd}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Archive_directory = fmt.Sprintf("%s/targets/archive", fileLocations.Base_directory)
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	} else {
		// Use PWD since don't really know where to put this type of thing
		pwd, err := os.Getwd()
		CheckErr(err)

		fileLocations := FileLocations{Base_directory: pwd}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Archive_directory = fmt.Sprintf("%s/targets/archive", fileLocations.Base_directory)
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	}
}

func CreateNecessaryDirectories(fileLocations FileLocations) {
	err := os.MkdirAll(fileLocations.Temp_directory, 0755)
	CheckErr(err)
	err = os.MkdirAll(fileLocations.Archive_directory, 0755)
	CheckErr(err)
	err = os.MkdirAll(fileLocations.Incoming_directory, 0755)
	CheckErr(err)
	err = os.MkdirAll(fileLocations.Results_directory, 0755)
	CheckErr(err)
}

func MoveTargetFileToTempDirectory(fileLocations FileLocations, targetFileName string) {
	old_path := fmt.Sprintf("%s/%s", fileLocations.Incoming_directory, targetFileName)
	new_path := fmt.Sprintf("%s/%s", fileLocations.Temp_directory, targetFileName)
	err := os.Rename(old_path, new_path)
	CheckErr(err)
}

func CopyTargetFileToArchiveDirectory(fileLocations FileLocations, targetFileName string) {
	old_path := fmt.Sprintf("%s/%s", fileLocations.Incoming_directory, targetFileName)
	new_path := fmt.Sprintf("%s/%s", fileLocations.Archive_directory, targetFileName)
	_, err := CopyFile(old_path, new_path)
	CheckErr(err)
}

func ProcessIncomingFilesDir(fileLocations FileLocations, accessKey string, secretKey string, sqlite_db string) {
	target_scan_ch := make(chan *TargetScan, 200)
	json_ch := make(chan string, 200)
	filename_ch := make(chan string, 200)
	new_scan_ch := make(chan CreateScanResponse, 200)
	scan_id_ch := make(chan int, 200)
	launched_scan_ch := make(chan LaunchScanResponse, 200)

	CreateNecessaryDirectories(fileLocations)
	defer os.RemoveAll(fileLocations.Temp_directory)

	nessus := MakeClient("localhost", "8834", accessKey, secretKey)
	targetFiles := nessus.TargetFilesOnDisk(fileLocations.Incoming_directory)
	nessus.ProcessTargetFiles(fileLocations, targetFiles, target_scan_ch)
	go nessus.AsyncBuildCreateScanJson(target_scan_ch, json_ch, filename_ch, targetFiles.FileNum)
	go nessus.AsyncCreateScan(json_ch, new_scan_ch, targetFiles.FileNum)
	go nessus.AsyncLaunchCreated(new_scan_ch, scan_id_ch, launched_scan_ch, targetFiles.FileNum)
	nessus.AsyncSaveLaunchedScan(sqlite_db, scan_id_ch, launched_scan_ch, filename_ch, fileLocations, targetFiles.FileNum)
}

func RetreieveLaunchedScanResults(fileLocations FileLocations, accessKey string, secretKey string, sqlite_db string) {
	export_ch := make(chan ExportScanResponse, 200)
	file_exported_ch := make(chan ExportScanResponse, 200)
	scan_result_ch := make(chan string, 200)
	scan_id_ch := make(chan string, 200)
	file_ch := make(chan bool, 200)

	CreateNecessaryDirectories(fileLocations)
	defer os.RemoveAll(fileLocations.Temp_directory)

	nessus := MakeClient("localhost", "8834", accessKey, secretKey)
	message := fmt.Sprintf("Connecting to SQLite3 database (%s)", sqlite_db)
	log.Print("[INFO] ", message)
	conn, err := sql.Open("sqlite3", sqlite_db)
	CheckErr(err)
	defer conn.Close()

	rows, err := conn.Query("SELECT * FROM active_scans ORDER BY request_id DESC;")
	CheckErr(err)
	defer rows.Close()
	numRows := 0
	for rows.Next() {
		var row DatabaseRow
		rows.Scan(&row.request_id, &row.method, &row.scan_uuid, &row.scan_id)
		go nessus.AsyncExportScan(row.scan_id, export_ch)
		go nessus.AsyncWaitForScan(row.scan_id, export_ch, file_exported_ch)
		go nessus.AsyncDownloadScan(row.scan_id, file_exported_ch, scan_result_ch, scan_id_ch)
		numRows++
	}

	successfulScans := 0
	for i := 0; i < numRows; i++ {
		nessus.AsyncSaveDownloadedScan(fileLocations.Results_directory, scan_result_ch, scan_id_ch, file_ch)
		if <-file_ch {
			successfulScans++
		}
	}

	log.Printf("[INFO] Successfully downloaded %d of %d results.", successfulScans, numRows)
}
