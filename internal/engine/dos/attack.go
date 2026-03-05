package dos

import (
	"sliverbane/internal/protocol"

	"github.com/hashicorp/yamux"
)

// Attack defines the interface for a DoS attack module
type Attack interface {
	Name() string
	Description() string
	Execute(session *yamux.Session, envKey *protocol.EnvelopeKey) error
}

var Registry = make(map[string]Attack)

func Register(attack Attack) {
	Registry[attack.Name()] = attack
}
