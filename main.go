package main

import (
	"fmt"
	"math/rand"
	"time"
	"crypto/tls"
	"net"
	"string"
	"flag"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/parnurzeal/gorequest"
)

func main() {
	for {
		d := flag.String("domains", nil, "Domains to scan network (separated by commas)")
		flag.Parse()

		domains := string.Split(*d, ",")
		subdomains := amass(domains)
		live := scanPorts(subdomains)
		validateInsecure(live)
		validateCert(live)

		time.Sleep(20 * time.Minute)
	}
}

func amass(domains []string) []string {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Setup the most basic amass configuration
	cfg := config.NewConfig()
	cfg.AddDomain("example.com")

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))

	e := enum.NewEnumeration(cfg, sys)
	if e == nil {
		return
	}
	defer e.Close()

	e.Start()
	return e.ExtractOutput(nil)
}

func scanPorts(hosts []string) []string {
	results := []string{}
	ports := []int{80, 443, 8000, 8080, 8443}

	for _, host := hosts {
		for _, port := ports {
			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.Dial("tcp", address, 3000 * time.Millisecond)
			if err != nil {
				continue
			}
			conn.Close()
			results = append(results, address)
		}
	}
	return results
}

func validateInsecure(hosts []string) {
	for _, host := hosts {
		if string.HasPrefix(host, "443") {
			continue
		}

		url := fmt.Sprintf("http://%s", host)
		request := gorequest.New()
		_, _, err := request.Get(url).
			RedirectPolicy(func(req Request, via []*Request) error {
				if req.URL.Scheme != "https" {
					fmt.Println("%s: [Issue] Insecure URL: %s (should redirect to HTTPS)", string(v), url)
					continue
				}
			}).
			Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
			End()

		if err != nil {
			v , _ := time.Now().UTC().MarshalText()
			fmt.Println("%s: [Info] Dead URL: %s", string(v), url)
		}
	}
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func validateCert(hosts []string) {
	for _, host := hosts {
		if !string.HasPrefix(host, "443") {
			continue
		}

		url := fmt.Sprintf("https://%s", host)
		request := gorequest.New()
		_, _, err := request.Get(url).
			Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
			End()

		if err != nil {
			v , _ := time.Now().UTC().MarshalText()
			fmt.Println("%s: [Info] Dead URL: %s", string(v), url)
			continue
		}

		conn, err := tls.Dial("tcp", host, nil)
		if err != nil {
			fmt.Println("%s: [Issue] No SSL certificate: %s", string(v), url)
		}
		err = conn.VerifyHostname(host)
		if err != nil {
			fmt.Println("%s: [Issue] Hostname doesn't match SSL certificate: %s", string(v), url)
		}

		timenow := time.Now().Format(time.RFC822)
		start := conn.ConnectionState().PeerCertificates[0].NotBefore.Format(time.RFC822)
		expiry := conn.ConnectionState().PeerCertificates[0].NotAfter.Format(time.RFC822)

		if !inTimeSpan(start, expiry, timenow) {
			fmt.Println("%s: [Issue] SSL certificate expired: %s", string(v), url)
		}
	}
}
