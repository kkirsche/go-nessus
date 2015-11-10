package goNessus

import (
	"log"
)

func checkErr(e error) {
	if e != nil {
		log.Print("[FATAL] ", "Received an error ", e, ".")
		panic(e)
	}
}
