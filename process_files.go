package goNessus

import (
	"fmt"     // For debugging purposes
	"os"      // For retrieving the PID
	"runtime" // For retrieving the current OS runtime (e.g. Linux, Windows or Darwin)
)

func ConstructFileLocations() FileLocations {
	if runtime.GOOS == "linux" {
		fileLocations := FileLocations{Base_directory: "/opt/scanner"}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	} else if runtime.GOOS == "darwin" {
		// Use PWD since don't really know where to put this type of thing
		pwd, err := os.Getwd()
		CheckErr(err)

		fileLocations := FileLocations{Base_directory: pwd}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	} else {
		// Use PWD since don't really know where to put this type of thing
		pwd, err := os.Getwd()
		CheckErr(err)

		fileLocations := FileLocations{Base_directory: pwd}
		fileLocations.Temp_directory = fmt.Sprintf("%s/temp%d", fileLocations.Base_directory, os.Getpid())
		fileLocations.Incoming_directory = fmt.Sprintf("%s/targets/incoming", fileLocations.Base_directory)
		fileLocations.Results_directory = fmt.Sprintf("%s/results", fileLocations.Base_directory)
		return fileLocations
	}
}

func CreateNecessaryDirectories(fileLocations FileLocations) {
	err := os.MkdirAll(fileLocations.Temp_directory, 0755)
	CheckErr(err)
	err = os.MkdirAll(fileLocations.Incoming_directory, 0755)
	CheckErr(err)
	err = os.MkdirAll(fileLocations.Results_directory, 0755)
	CheckErr(err)
}

func ProcessIncomingFilesDir(fileLocations FileLocations, accessKey string, secretKey string, sqlite_db string) {
	target_scan_ch := make(chan *TargetScan, 10)
	json_ch := make(chan string, 10)
	new_scan_ch := make(chan CreateScanResponse, 10)
	scan_id_ch := make(chan int, 10)
	launched_scan_ch := make(chan LaunchScanResponse, 10)

	nessus := MakeClient("localhost", "8834", accessKey, secretKey)
	targetFiles := nessus.TargetFilesOnDisk(fileLocations.Incoming_directory)
	nessus.ProcessTargetFiles(targetFiles, target_scan_ch)
	go nessus.BuildCreateScanJson(target_scan_ch, json_ch, targetFiles.FileNum)
	go nessus.CreateScan(json_ch, new_scan_ch, targetFiles.FileNum)
	go nessus.AsyncLaunchCreated(new_scan_ch, scan_id_ch, launched_scan_ch, targetFiles.FileNum)
	nessus.SaveLaunchedScan(sqlite_db, scan_id_ch, launched_scan_ch, targetFiles.FileNum)
}

func RetreieveLaunchedScanResults(fileLocations FileLocations, accessKey string, secretKey string, sqlite_db string) {
	export_ch := make(chan ExportScanResponse, 10)
	scan_result_ch := make(chan string, 10)
	file_ch := make(chan bool, 10)
	scan_id := "292"

	nessus := MakeClient("localhost", "8834", accessKey, secretKey)
	go nessus.ExportScan(scan_id, export_ch)
	go nessus.DownloadScan(scan_id, export_ch, scan_result_ch)
	go nessus.SaveDownloadedScan(scan_id, fileLocations.Results_directory, scan_result_ch, file_ch)
	<-file_ch
}
