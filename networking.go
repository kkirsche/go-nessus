package go_nessus

import (
	"crypto/tls" // To disable SSL verification
	"fmt"
	"github.com/parnurzeal/gorequest" // For HTTP requests with JSON
	"log"
)

func (nessus Nessus) performPostWithArgs(url string, opts string,
	str_ch chan string) {
	request := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, body, errs := request.Post(
		fmt.Sprintf("https://%s:%s/%s", nessus.Ip, nessus.Port, url)).
		Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", nessus.AccessKey, nessus.SecretKey)).
		Send(opts).
		End()

	for _, err := range errs {
		if err != nil {
			log.Fatal("[FATAL]", err)
			panic(err)
		}
	}
	str_ch <- resp.Status
	str_ch <- string(body)
}

func (nessus Nessus) performPost(url string, channel chan string) {
	request := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, body, errs := request.Post(
		fmt.Sprintf("https://%s:%s/%s", nessus.Ip, nessus.Port, url)).
		Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", nessus.AccessKey, nessus.SecretKey)).
		End()

	for _, err := range errs {
		if err != nil {
			log.Fatal(err)
			panic(err)
		}
	}

	channel <- resp.Status
	channel <- string(body)
}
