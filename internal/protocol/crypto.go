package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const (
	EdDSA                         uint16 = 0x6445
	RawSigSize                           = 2 + 8 + ed25519.SignatureSize
	mtlsEnvelopeSigningSeedPrefix        = "env-signing-v1:"
)

type EnvelopeKey struct {
	PrivateKey ed25519.PrivateKey
	KeyID      uint64
}

// DeriveEnvelopeKey deterministically generates the Ed25519 signing keypair
// matching the target implant using its extracted Age private key.
func DeriveEnvelopeKey(agePrivateKey string) (*EnvelopeKey, error) {
	if agePrivateKey == "" {
		return nil, fmt.Errorf("missing age private key")
	}

	seed := sha256.Sum256([]byte(mtlsEnvelopeSigningSeedPrefix + agePrivateKey))
	priv := ed25519.NewKeyFromSeed(seed[:])

	pub := priv.Public().(ed25519.PublicKey)
	digest := blake2b.Sum256(pub)
	keyID := binary.LittleEndian.Uint64(digest[:8])

	return &EnvelopeKey{
		PrivateKey: priv,
		KeyID:      keyID,
	}, nil
}
