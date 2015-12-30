// Package goNessus provides a Golang based interface to Nessus 6
package goNessus

import (
	"fmt"
)

// Returns the agent list for the given scanner.
//
// This request requires standard user permissions. Users with this role can
// create scans, policies, and reports.
func (nessus *Nessus) ListAgents(scanner_id int, str_ch chan string) {
	agents_ch := make(chan string)
	url := fmt.Sprintf("scanners/%d/agents", scanner_id)
	nessus.PerformGet(url, agents_ch)
	status, body := <-agents_ch, <-agents_ch
	str_ch <- status
	str_ch <- body
}
