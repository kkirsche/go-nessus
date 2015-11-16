package goNessus

import (
	"log"
)

func CheckErr(e error) {
	if e != nil {
		log.Panic("[FATAL] ", "Received an error ", e, ".")
	}
}
