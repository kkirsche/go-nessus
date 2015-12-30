package goNessus

import (
	"log"
)

// Used to check if an error is not equal to nil. If it is, throw a fatal error
// using the log package.
func CheckErr(e error) {
	if e != nil {
		log.Panic("[FATAL] ", "Received an error ", e, ".")
	}
}
