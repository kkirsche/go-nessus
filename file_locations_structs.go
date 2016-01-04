package goNessus

// FileLocations represents where files will be found on a system. Specifically
// we have the temporary directory where we store stuff while processing,
// archive directory where we store processed files, incoming directory where
// target files are stored prior to being processed, and results directory where
// we store scan result CSV files.
type FileLocations struct {
	Base_directory     string
	Temp_directory     string
	Archive_directory  string
	Incoming_directory string
	Results_directory  string
}
