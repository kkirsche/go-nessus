package goNessus

import (
	"crypto/tls" // To disable SSL verification
	"fmt"
	"github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/parnurzeal/gorequest" // For HTTP requests with JSON
	"log"
)

func (nessus Nessus) PerformGet(url string, str_ch chan string) {
	request := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, body, errs := request.Get(
		fmt.Sprintf("https://%s:%s/%s", nessus.Ip, nessus.Port, url)).
		Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", nessus.AccessKey, nessus.SecretKey)).
		End()

	for _, err := range errs {
		if err != nil {
			log.Panic("[FATAL] ", err)
		}
	}

	str_ch <- resp.Status
	str_ch <- string(body)
}

func (nessus Nessus) PerformPostWithArgs(url string, opts string,
	str_ch chan string) {

	request := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, body, errs := request.Post(
		fmt.Sprintf("https://%s:%s/%s", nessus.Ip, nessus.Port, url)).
		Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", nessus.AccessKey, nessus.SecretKey)).
		Send(opts).
		End()

	for _, err := range errs {
		if err != nil {
			log.Panic("[FATAL] ", err)
		}
	}

	str_ch <- resp.Status
	str_ch <- string(body)
}

func (nessus Nessus) PerformPost(url string, channel chan string) {
	request := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, body, errs := request.Post(
		fmt.Sprintf("https://%s:%s/%s", nessus.Ip, nessus.Port, url)).
		Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", nessus.AccessKey, nessus.SecretKey)).
		End()

	for _, err := range errs {
		if err != nil {
			log.Panic("[FATAL] ", err)
		}
	}

	channel <- resp.Status
	channel <- string(body)
}
