package transport

import (
	"crypto/tls"
	"fmt"
	"net"
)

type MTLS struct{}

func NewMTLS() *MTLS {
	return &MTLS{}
}

func (m *MTLS) Connect(endpoint string, config *tls.Config) (net.Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("TLS config is required for mTLS transport")
	}

	conn, err := tls.Dial("tcp", endpoint, config)
	if err != nil {
		return nil, fmt.Errorf("mTLS connection failed: %w", err)
	}

	return conn, nil
}
