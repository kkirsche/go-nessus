package goNessus

import (
	"fmt"
)

func (nessus *Nessus) ListAgents(scanner_id int, str_ch chan string) {
	agents_ch := make(chan string)
	url := fmt.Sprintf("scanners/%d/agents", scanner_id)
	nessus.PerformGet(url, agents_ch)
	status, body := <-agents_ch, <-agents_ch
	str_ch <- status
	str_ch <- body
}
