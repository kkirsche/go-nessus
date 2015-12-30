package goNessus

// DatabaseRow is used to represent a single row in the SQLite3 database
type DatabaseRow struct {
	Request_id int
	Method     string
	Scan_uuid  string
	Scan_id    string
}
