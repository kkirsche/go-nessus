package goNessus

type ExportScanResponse struct {
	File int `json:"file"`
}

type ExportScanStatusResponse struct {
	Status string `json:"status"`
}
