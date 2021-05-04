package check

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func defaultLookup(collector Collector, host string, timing bool) ([]string, error) {
	if timing {
		start := time.Now()
		defer func() {
			collector <- CollectedInfo{
				Name:     "time resolve",
				Duration: time.Since(start),
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rch := make(chan []string, 1)
	ech := make(chan error, 1)

	go func() {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			ech <- err
			return
		}
		ips := make([]string, 0)
		for _, ia := range addrs {
			ipStr := ia.IP.String()
			if isIPv4(ipStr) {
				ips = append(ips, ipStr)
			}
		}
		rch <- ips
	}()

	select {
	case ips := <-rch:
		return ips, nil
	case err := <-ech:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func isIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func externalLookup(collector Collector, resolver, host string, timing bool) ([]string, error) {
	if timing {
		start := time.Now()
		defer func() {
			collector <- CollectedInfo{
				Name:     "time resolve",
				Duration: time.Since(start),
			}
		}()
	}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	client := &dns.Client{
		Timeout:      10 * time.Second,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	r, _, err := client.ExchangeContext(context.Background(), m, resolver)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("unable to query: %d", r.Rcode)
	}

	results := make([]string, 0, len(r.Answer))

	for _, a := range r.Answer {
		aRecord, ok := a.(*dns.A)
		if !ok {
			continue
		}
		results = append(results, aRecord.A.String())
	}

	return results, nil
}
