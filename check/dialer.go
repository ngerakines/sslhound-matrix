package check

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"
)

type tlsCheckerDialer struct {
	Timeout time.Duration
}

type connectionStateProvider interface {
	ConnectionState() tls.ConnectionState
	io.Closer
}

func (cd tlsCheckerDialer) Dial(ctx context.Context, host, port, ip string) (connectionStateProvider, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		Time:               func() time.Time { return time.Now().UTC() },
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", net.JoinHostPort(ip, port), tlsConfig)
}
