package goNessus

// ExportScanResponse represents the JSON received from Nessus when exporting a scan
type ExportScanResponse struct {
	File int `json:"file"`
}

// ExportScanStatusResponse represents the JSON received from Nessus when
// checking the status of a scan export.
type ExportScanStatusResponse struct {
	Status string `json:"status"`
}
