package goNessus

type DatabaseRow struct {
	request_id int
	method     string
	scan_uuid  string
	scan_id    string
}
