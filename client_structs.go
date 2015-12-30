// Package goNessus provides a Golang based interface to Nessus 6
package goNessus

// Nessus struct is used to contain information about a Nessus scanner. This
// will be used to connect to the scanner and make API requests.
type Nessus struct {
	Ip        string
	Port      string
	AccessKey string
	SecretKey string
	Token     string
}
