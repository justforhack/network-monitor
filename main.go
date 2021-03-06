package main

import (
	"context"
	"crypto/tls"
	"os"
	"fmt"
	"flag"
	"time"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"io/ioutil"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"
)

func main() {
	domains := flag.String("domains", "", "Domains to scan network (separated by commas)")
	flag.Parse()

	if *domains == "" {
		fmt.Println("Please provide domains to scan")
		return
	}

	subdomains := amass(*domains)
	if len(subdomains) == 0 {
		fmt.Println("ERROR: Cannot perform subdomains enumeration")
		return
	}

	live := scanPorts(subdomains)
	validateInsecure(live)
	validateCert(live)
}

func amass(domains string) []string {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Setup the most basic amass configuration
	cfg := config.NewConfig()
	for _, domain := range strings.Split(domains, ",") {
		cfg.AddDomain(domain)
	}

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

	e.Start(context.TODO())

	homedir, err := os.UserHomeDir()

	db, err := ioutil.ReadFile(homedir + "/.config/amass/amass.txt")
	if err != nil {
		return []string{}
	}
	return strings.Split(string(db), "\n")
}

func scanPorts(hosts []string) []string {
	results := []string{}
	ports := []int{80, 443, 8080, 8443}

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
	v := time.Now().Format(time.RFC3339)

	var secureRedirect bool = false

	for _, host := range hosts {
		if strings.HasPrefix(host, "443") {
			continue
		}

		url := fmt.Sprintf("http://%s", host)
		
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme == "https" {
					secureRedirect = true
				}
				return nil
			},
		}
		_, err := client.Get(url)

		if err != nil {
			continue
		}

		if !secureRedirect {
			fmt.Printf("%s %s - Insecure HTTP protocol (should redirect to HTTPS)", string(v), host)
		}
	}
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func validateCert(hosts []string) {
	var c *tls.Conn
	var e error

	v := time.Now().Format(time.RFC3339)
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	versions := map[uint16]string{
		tls.VersionSSL30: "SSLv3",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
	}

	for _, host := range hosts {
		if !strings.HasPrefix(host, "443") {
			continue
		}

		url := fmt.Sprintf("https://%s", host)

		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					c, e = tls.Dial(network, addr, tlsConfig)
					return c, e
				},
			},
		}
		_, err := client.Get(url)

		if err != nil {
			continue
		}

		if c.ConnectionState().Version != tls.VersionTLS12 {
			ver := c.ConnectionState().Version
			fmt.Printf("%s %s - Server uses %s which is unsecure", string(v), host, versions[ver])
		}

		conn, err := tls.Dial("tcp", host, nil)
		if err != nil {
			fmt.Printf("%s %s - No SSL certificate", string(v), host)
		}
		err = conn.VerifyHostname(host)
		if err != nil {
			fmt.Printf("%s %s - Hostname doesn't match SSL certificate", string(v), host)
		}

		for _, cert := range conn.ConnectionState().PeerCertificates {
			timenow, _ := time.Parse(time.RFC822, time.Now().Format("2006-01-02 15:04:05 UTC"))
			start, _ := time.Parse(time.RFC822, cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
			expiry, _ := time.Parse(time.RFC822, cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

			if !inTimeSpan(start, expiry, timenow) {
				fmt.Printf("%s %s - SSL certificate expired", string(v), host)
				break
			}
		}
	}
}
