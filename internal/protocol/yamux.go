package protocol

import (
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

const YamuxPreface = "MUX/1"

// SetupYamuxWrites the preface and sets up a Yamux client session on the given connection
func SetupYamux(conn net.Conn) (*yamux.Session, error) {
	if _, err := conn.Write([]byte(YamuxPreface)); err != nil {
		return nil, fmt.Errorf("write yamux preface: %w", err)
	}

	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard // or a custom logger if we want less noise
	config.EnableKeepAlive = true
	// matches sliver's yamux config
	session, err := yamux.Client(conn, config)
	if err != nil {
		return nil, fmt.Errorf("yamux client setup: %w", err)
	}

	return session, nil
}
