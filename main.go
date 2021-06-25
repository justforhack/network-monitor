package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"
	"crypto/tls"
	"net"
	"strings"
	"http"
	"flag"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/parnurzeal/gorequest"
)

func main() {
	for {
		domains := flag.String("domains", "", "Domains to scan network (separated by commas)")
		flag.Parse()

		if *domains == "" {
			panic("Please provide domains to scan")
		}

		subdomains := amass(*domains)
		live := scanPorts(subdomains)
		validateInsecure(live)
		validateCert(live)

		time.Sleep(20 * time.Minute)
	}
}

func amass(domains string) []string {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Setup the most basic amass configuration
	cfg := config.NewConfig()
	cfg.AddDomain(domains)

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return []string{}
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))

	e := enum.NewEnumeration(cfg, sys)
	if e == nil {
		return []string{}
	}
	defer e.Close()

	ctx := context.Background()
	e.Start(ctx)

	return e.ExtractOutput(nil)
}

func scanPorts(hosts []string) []string {
	results := []string{}
	ports := []int{80, 443, 8000, 8080, 8443}

	for _, host := range hosts {
		for _, port := range ports {
			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", address, 3000 * time.Millisecond)
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
	v , _ := time.Now().UTC().MarshalText()

	var secureRedirect bool = false

	for _, host := range hosts {
		if strings.HasPrefix(host, "443") {
			continue
		}

		url := fmt.Sprintf("http://%s", host)
		request := gorequest.New()
		_, _, err := request.Get(url).
			RedirectPolicy(func(req http.Request, via []*http.Request) error {
				if req.URL.Scheme == "https" {
					secureRedirect = true
				}
			}).
			Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
			End()

		if err != nil {
			fmt.Println("%s: [Info] Dead URL: %s", string(v), url)
		}

		if !secureRedirect {
			fmt.Println("%s: [Issue] Insecure URL: %s (should redirect to HTTPS)", string(v), url)
		}
	}
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func validateCert(hosts []string) {
	v , _ := time.Now().UTC().MarshalText()

	for _, host := range hosts {
		if !strings.HasPrefix(host, "443") {
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
		error = conn.VerifyHostname(host)
		if error != nil {
			fmt.Println("%s: [Issue] Hostname doesn't match SSL certificate: %s", string(v), url)
		}

		timenow := time.Parse(time.RFC822, time.Now().Format("2006-01-02 15:04:05 UTC"))
		start := time.Parse(time.RFC822, conn.ConnectionState().PeerCertificates[0].NotBefore.Format("2006-01-02 15:04:05 UTC"))
		expiry := time.Parse(time.RFC822, conn.ConnectionState().PeerCertificates[0].NotAfter.Format("2006-01-02 15:04:05 UTC"))

		if !inTimeSpan(start, expiry, timenow) {
			fmt.Println("%s: [Issue] SSL certificate expired: %s", string(v), url)
		}
	}
}
