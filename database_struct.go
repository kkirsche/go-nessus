package goNessus

type DatabaseRow struct {
	Request_id int
	Method     string
	Scan_uuid  string
	Scan_id    string
}
