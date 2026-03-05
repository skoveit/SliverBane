package transport

import (
	"crypto/tls"
	"net"
)

// Transport defines the interface for underlying C2 communication.
type Transport interface {
	Connect(endpoint string, config *tls.Config) (net.Conn, error)
}
