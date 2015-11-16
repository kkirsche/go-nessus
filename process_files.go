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
	new_path := fmt.Sprintf("%s/%s", fileLocations.Incoming_directory, targetFileName)
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
	nessus.AsyncSaveLaunchedScan(sqlite_db, scan_id_ch, launched_scan_ch, filename_ch, targetFiles.FileNum)
}

func RetreieveLaunchedScanResults(fileLocations FileLocations, accessKey string, secretKey string, sqlite_db string) {
	export_ch := make(chan ExportScanResponse, 200)
	scan_result_ch := make(chan string, 200)
	file_ch := make(chan bool, 200)
	scan_id := "292"

	CreateNecessaryDirectories(fileLocations)
	defer os.RemoveAll(fileLocations.Temp_directory)

	nessus := MakeClient("localhost", "8834", accessKey, secretKey)
	go nessus.AsyncExportScan(scan_id, export_ch)
	go nessus.AsyncDownloadScan(scan_id, export_ch, scan_result_ch)
	go nessus.AsyncSaveDownloadedScan(scan_id, fileLocations.Results_directory, scan_result_ch, file_ch)
	<-file_ch
}
