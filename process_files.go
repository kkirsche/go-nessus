package goNessus

import (
	"database/sql"                                                                           // For using the SQLite3 Library
	"fmt"                                                                                    // For debugging purposes
	_ "github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/mxk/go-sqlite/sqlite3" // SQLite3 Database Communications
	"github.com/kkirsche/go-scp"                                                             // Used to retrieve files over SSH channel
	"golang.org/x/crypto/ssh"                                                                // For SSH client connections
	"log"                                                                                    // For logging
	"os"                                                                                     // For retrieving the PID
	"regexp"                                                                                 // To determine all files in a path using Globs
	"runtime"                                                                                // For retrieving the current OS runtime (e.g. Linux, Windows or Darwin)
	"strings"                                                                                // To split strings on newlines
)

// Construct file locations of of scanner resources based on the operating system.
//
// Example:
//
// 	fileLocations := goNessus.ConstructFileLocations()
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

// Create any directories with 755 permissions from ConstructFileLocations which
// do not exist.
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

// Moves target file to temporary directory as defined in ConstructFileLocations.
// Target file is the file stating which type of scan will be used and what hosts
// will be scanned.
func MoveTargetFileToTempDirectory(fileLocations FileLocations, targetFileName string) {
	old_path := fmt.Sprintf("%s/%s", fileLocations.Incoming_directory, targetFileName)
	new_path := fmt.Sprintf("%s/%s", fileLocations.Temp_directory, targetFileName)
	err := os.Rename(old_path, new_path)
	CheckErr(err)
}

// Creates a copy of the target file and puts it in the archive directory as
// definied in ConstructFileLocations. The target file is the file stating which
// type of scan will be used and what hosts will be scanned.
func CopyTargetFileToArchiveDirectory(fileLocations FileLocations, targetFileName string) {
	old_path := fmt.Sprintf("%s/%s", fileLocations.Incoming_directory, targetFileName)
	new_path := fmt.Sprintf("%s/%s", fileLocations.Archive_directory, targetFileName)
	_, err := CopyFile(old_path, new_path)
	CheckErr(err)
}

// Processes each target file in the incoming directory as defined by
// ConstructFileLocations. This takes each file, parses it, creates a JSON
// object to send to Nessus to create a scan, creates the scan, launches the scan,
// and records the information about the scan in an SQLite database.
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

// RetreieveLaunchedScanResults works through the SQLite database from
// ProcessIncomingFilesDir, exports each scan, waits for the export to finish,
// then downloads the scan and saves it to the results directory from
// ConstructFileLocations
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
		rows.Scan(&row.Request_id, &row.Method, &row.Scan_uuid, &row.Scan_id)
		go nessus.AsyncExportScan(row.Scan_id, export_ch)
		go nessus.AsyncWaitForScan(row.Scan_id, export_ch, file_exported_ch)
		go nessus.AsyncDownloadScan(row.Scan_id, file_exported_ch, scan_result_ch, scan_id_ch)
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

// Connects to a remote scanner over SSH, creates a list of all available result
// files, then SCP's each of them (*.csv) to the local machine.
//
// Example:
//
//	scpKeyFile := goScp.SshKeyfile{Path: "/Users/example/.ssh", Filename: "id_rsa.pub"}
// 	scpCredentials := goScp.SshCredentials{Username: "example"}
// 	scpRemoteMachine := goScp.RemoteMachine{Host: "192.168.0.1", Port: "8022"}
//
// 	client, err := goScp.Connect(scpKeyFile, scpCredentials, scpRemoteMachine, false)
// 	if err != nil {
// 		log.Fatal("Failed to connect: " + err.Error())
// 	}
//
// 	remoteFilePath := "/opt/scanner/results"
// 	localFilePath := "/Users/example/nessusResults"
// 	goNessus.ScpRemoteResultsToLocal(client, remoteFilePath, localFilePath)
func ScpRemoteResultsToLocal(client *ssh.Client, remoteFilePath string, localFilePath string) {
	results, err := goScp.ExecuteCommand(client, "ls -1 "+remoteFilePath)
	if err != nil {
		log.Fatal("Error getting list of files")
	}

	filenameArray := strings.Split(results, "\n")

	var matches []string
	for _, file := range filenameArray {
		match, err := regexp.MatchString(".+.csv", file)
		if err != nil {
			log.Fatal(err)
		}
		if match {
			matches = append(matches, file)
		}
	}

	for _, file := range matches {
		err = goScp.CopyRemoteFileToLocal(client, remoteFilePath, file, localFilePath, "")
		if err != nil {
			log.Fatal("Error copying file")
		}
	}
}
