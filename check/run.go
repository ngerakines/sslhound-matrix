package check

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

// July 2012 is the CAB Forum deadline for when CAs must stop issuing certificates valid for more than 5 years.
var jul2012 = time.Date(2012, time.July, 1, 0, 0, 0, 0, time.UTC).Add(-1 * time.Nanosecond)

// April 2015 is the CAB Forum deadline for when CAs must stop issuing certificates valid for more than 39 months.
var apr2015 = time.Date(2015, time.April, 1, 0, 0, 0, 0, time.UTC).Add(-1 * time.Nanosecond)

// September 2020 is the Apple deadline for when CAs must stop issuing certificates valid for more than 13 months.
var sep2020 = time.Date(2020, time.September, 1, 0, 0, 0, 0, time.UTC).Add(-1 * time.Nanosecond)

// RunCheck executes checks and collects facts for provided host and port.
func RunCheck(collector Collector, host, port string, opts ...Option) error {
	options := Options{
		ctx:           context.Background(),
		collectTiming: false,
	}
	for _, opt := range opts {
		opt(&options)
	}

	if options.collectTiming {
		start := time.Now()
		defer func() {
			collector <- CollectedInfo{
				Name:     "time check",
				Duration: time.Since(start),
			}
		}()
	}
	now := time.Now()

	var err error
	var ips []string

	if options.nameserver == "" {
		ips, err = defaultLookup(collector, host, options.collectTiming)
	} else {
		ips, err = externalLookup(collector, options.nameserver, host, options.collectTiming)
	}

	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("host must resolve to one or more IP address")
	}

	for _, ip := range ips {
		collector <- CollectedInfo{
			Name:  "resolved",
			Value: ip,
		}
	}

	ipCerts, err := collectedResolvedCertificates(options.ctx, collector, host, port, ips, options.collectTiming)
	if err != nil {
		return err
	}

	if err = verifyCertificates(collector, ipCerts); err != nil {
		return err
	}

	certificates := ipCerts[ips[0]]

	if err := certificates[0].VerifyHostname(host); err != nil {
		return err
	}

	if err := verifyServerCertificate(host, certificates); err != nil {
		return err
	}

	if certificates[0].NotAfter.Before(now) {
		return fmt.Errorf("certificate expired")
	}

	if len(certificates) == 1 {
		collector <- CollectedInfo{
			Name:  "warning",
			Value: "certificate chain has one certificate",
		}
	}

	if certificates[0].IsCA {
		collector <- CollectedInfo{
			Name:  "warning",
			Value: "certificate authority",
		}
	}

	if len(certificates) > 1 {
		err = isCertificateRevokedByOCSP(options.ctx, collector, certificates[0], certificates[1], options.collectTiming)
		if err != nil {
			collector <- CollectedInfo{
				Name:  "warning",
				Value: err.Error(),
			}
		}
	}

	if _, _, ok := isValidExpiry(certificates[0]); !ok {
		return err
	}

	if certificates[0].NotAfter.Before(now.AddDate(0, 0, 1)) {
		return fmt.Errorf("certificate expires tomorrow: %s", certificates[0].NotAfter.String())
	}

	if certificates[0].NotAfter.Before(now.AddDate(0, 0, 7)) {
		collector <- CollectedInfo{
			Name:  "warning",
			Value: fmt.Sprintf("certificate expires within 7 days: %s", certificates[0].NotAfter.String()),
		}
	} else if certificates[0].NotAfter.Before(now.AddDate(0, 0, 30)) {
		collector <- CollectedInfo{
			Name:  "warning",
			Value: fmt.Sprintf("certificate expires within 30 days: %s", certificates[0].NotAfter.String()),
		}
	}

	if len(certificates[0].Subject.Names) == 0 {
		collector <- CollectedInfo{
			Name:  "warning",
			Value: "no subject",
		}
	} else {
		if certificates[0].Subject.CommonName == "" {
			collector <- CollectedInfo{
				Name:  "warning",
				Value: "no common name",
			}
		}
	}

	for _, cert := range certificates {
		switch cert.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			return fmt.Errorf("bad signature algorithm: %s", cert.SignatureAlgorithm)
		}
		// fmt.Println("EXTRA", i, "sigalg", cert.SignatureAlgorithm)
		// fmt.Println("EXTRA", i, "pubkeyalg", cert.PublicKeyAlgorithm)
	}

	uniqueNames := make(map[string]bool)
	for _, certificate := range certificates {
		for _, name := range certificate.DNSNames {
			if name == host {
				continue
			}
			uniqueNames[name] = true
		}
	}
	for name := range uniqueNames {
		collector <- CollectedInfo{
			Name:  "name",
			Value: name,
		}
	}

	return nil
}

func collectedResolvedCertificates(ctx context.Context, collector Collector, host, port string, ips []string, timing bool) (map[string][]*x509.Certificate, error) {
	results := make(map[string][]*x509.Certificate)

	dialer := tlsCheckerDialer{
		Timeout: 10 * time.Second,
	}

	for _, ip := range ips {
		var connStart time.Time
		if timing {
			connStart = time.Now()
		}
		conn, err := dialer.Dial(ctx, host, port, ip)
		if err != nil {
			return nil, err
		}
		state := conn.ConnectionState()
		certificates := state.PeerCertificates

		if err = conn.Close(); err != nil {
			return nil, err
		}

		results[ip] = certificates
		if timing {
			collector <- CollectedInfo{
				Name:     "time collect",
				Value:    ip,
				Duration: time.Since(connStart),
			}
		}
	}

	return results, nil
}

func verifyCertificates(collector Collector, certs map[string][]*x509.Certificate) error {

	var firstFingerprints []string

	for _, certificates := range certs {
		if len(certs) == 0 {
			return fmt.Errorf("no certificates found")
		}

		var fingerprints []string
		for _, certificate := range certificates {
			fingerprintHash := sha256.Sum256(certificate.Raw)
			fingerprints = append(fingerprints, hex.EncodeToString(fingerprintHash[:]))
		}

		if firstFingerprints == nil {
			firstFingerprints = fingerprints
			continue
		}

		if firstFingerprints[0] != fingerprints[0] {
			return fmt.Errorf("different certificates found")
		}

	}
	if len(firstFingerprints) > 0 {
		collector <- CollectedInfo{
			Name:  "fingerprint",
			Value: firstFingerprints[0],
		}
	}

	return nil
}

func isCertificateRevokedByOCSP(ctx context.Context, collector Collector, clientCert, issuerCert *x509.Certificate, timing bool) error {
	if timing {
		start := time.Now()
		defer func() {
			collector <- CollectedInfo{
				Name:     "time ocsp",
				Duration: time.Since(start),
			}
		}()
	}

	if len(clientCert.OCSPServer) == 0 {
		return nil
	}

	ocspURL, err := url.Parse(clientCert.OCSPServer[0])
	if err != nil {
		return err
	}

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL.String(), bytes.NewBuffer(buffer))
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "application/ocsp-request")
	request.Header.Add("Accept", "application/ocsp-response")
	request.Header.Add("host", ocspURL.Host)
	request.Header.Add("User-Agent", "certdialer")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}
	httpResponse, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return err
	}

	if ocspResponse.Status == ocsp.Revoked {
		return fmt.Errorf("certificate is revoked")
	}
	return nil
}

// isValidExpiry determines if a certificate is valid for an acceptable
// length of time per the CA/Browser Forum baseline requirements.
// See https://cabforum.org/wp-content/uploads/CAB-Forum-BR-1.3.0.pdf
func isValidExpiry(c *x509.Certificate) (int, int, bool) {
	mm := maxMonths(c.NotBefore)
	mv := monthsValid(c.NotBefore, c.NotAfter)
	return mm, mv, monthsValid(c.NotBefore, c.NotAfter) <= maxMonths(c.NotBefore)
}

func maxMonths(issued time.Time) int {
	if issued.After(sep2020) {
		return 13
	} else if issued.After(apr2015) {
		return 39
	} else if issued.After(jul2012) {
		return 60
	}
	return 120
}

func monthsValid(issued, expiry time.Time) int {
	years := expiry.Year() - issued.Year()
	months := years*12 + int(expiry.Month()) - int(issued.Month())

	// Round up if valid for less than a full month
	if expiry.Day() > issued.Day() {
		months++
	}
	return months
}

func verifyServerCertificate(host string, certificates []*x509.Certificate) error {
	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := certificates[0].Verify(opts)
	if err != nil {
		return err
	}

	switch certificates[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certificates[0].PublicKey)
	}

	return err
}
