package goNessus

import (
	"bufio"         // For reading in a file line by line
	"fmt"           // For debugging purposes
	"log"           // Used for logging application events
	"os"            // Used to interact with the host operating system
	"path/filepath" // Use to work with filename paths
	"regexp"        // Regular expressions!
	"runtime"       // Runtime allows us to detect what OS we are running on
	"strings"       // Strings allows us to split strings apart
)

func (nessus *Nessus) TargetFilesOnDisk(base_path string) *TargetFiles {
	path_glob := fmt.Sprintf("%s/*.txt", base_path)
	str_arr, err := filepath.Glob(path_glob)
	if err != nil {
		log.Panic(err)
	}
	return &TargetFiles{Filepaths: str_arr, FileNum: len(str_arr)}
}

func (nessus *Nessus) ProcessTargetFiles(fileLocations FileLocations, targetFiles *TargetFiles, target_scan_ch chan *TargetScan) {
	processed_ch := make(chan *TargetScan)
	go func() {
		for _, path := range targetFiles.Filepaths {
			var split_path []string
			if runtime.GOOS == "windows" {
				split_path = strings.Split(path, "\\")
			} else {
				split_path = strings.Split(path, "/")
			}

			fileName := split_path[len(split_path)-1] // ::: the filename from the path

			go processFile(path, fileName, fileLocations, processed_ch)
		}
	}()

	go func() {
		for i := 0; i < targetFiles.FileNum; i++ {
			targetFile := <-processed_ch
			target_scan_ch <- targetFile
		}
	}()
}

func processFile(path string, fileName string, fileLocations FileLocations, processed_ch chan *TargetScan) {
	file, err := os.Open(path)
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	request_id_ch := make(chan string)
	method_ch := make(chan string)
	ips_ch := make(chan string)

	lines := 0
	for scanner.Scan() {
		go processLine(scanner.Text(), request_id_ch, method_ch, ips_ch)
		lines += 1
	}

	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	requestid, method, ips := <-request_id_ch, <-method_ch, []string{<-ips_ch}

	for i := 0; i < (lines - 3); i++ {
		ips = append(ips, <-ips_ch)
	}

	processed_ch <- &TargetScan{
		RequestID: requestid,
		Method:    method,
		FileName:  fileName,
		IPs:       ips,
	}

	CopyTargetFileToArchiveDirectory(fileLocations, fileName)
	MoveTargetFileToTempDirectory(fileLocations, fileName)
}

func processLine(line string, request_id_ch chan string,
	method_ch chan string, ips_ch chan string) {

	requestIdRegexp := regexp.MustCompile(`requestid:.*(?P<RequestId>\d+)`)
	requestid := requestIdRegexp.FindString(line)

	methodRegexp := regexp.MustCompile(`method:.*(?P<Method>\w+)`)
	method := methodRegexp.FindString(line)

	ipRegexp := regexp.MustCompile(`(\d{1,3}\.){3}(\d{1,3})`)
	ip := ipRegexp.FindString(line)

	if requestid != "" {
		request_id_ch <- requestid[12:]
	}

	if method != "" {
		method_ch <- method[8:]
	}

	if ip != "" {
		ips_ch <- ip[:]
	}
}
