package goNessus

type TargetFiles struct {
	Filepaths []string
	FileNum   int
}

type TargetScan struct {
	RequestID string
	Method    string
	FileName  string
	IPs       []string
}
