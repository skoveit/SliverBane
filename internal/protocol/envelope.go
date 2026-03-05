package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sliverbane/protobuf/sliverpb"

	"google.golang.org/protobuf/proto"
)

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// WriteEnvelope marshals and signs a protobuf envelope matching Sliver's wire format
func WriteEnvelope(w io.Writer, envelope *sliverpb.Envelope, key *EnvelopeKey) error {
	if envelope == nil {
		return errors.New("nil envelope")
	}

	data, err := proto.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	rawSigBuf := make([]byte, RawSigSize)
	binary.LittleEndian.PutUint16(rawSigBuf[:2], EdDSA)
	binary.LittleEndian.PutUint64(rawSigBuf[2:10], key.KeyID)
	copy(rawSigBuf[10:], ed25519.Sign(key.PrivateKey, data))

	if err := writeAll(w, rawSigBuf); err != nil {
		return fmt.Errorf("write raw signature: %w", err)
	}

	var dataLengthBuf [4]byte
	binary.LittleEndian.PutUint32(dataLengthBuf[:], uint32(len(data)))
	if err := writeAll(w, dataLengthBuf[:]); err != nil {
		return fmt.Errorf("write data length: %w", err)
	}
	if err := writeAll(w, data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

// ReadEnvelope reads an encrypted envelope from the connection
func ReadEnvelope(r io.Reader) (*sliverpb.Envelope, error) {
	rawSigBuf := make([]byte, RawSigSize)
	if _, err := io.ReadFull(r, rawSigBuf); err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}

	dataLengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, dataLengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	if dataLength <= 0 || dataLength > 1024*1024*50 { // Sanity check max 50MB
		return nil, fmt.Errorf("invalid envelope size: %d", dataLength)
	}

	dataBuf := make([]byte, dataLength)
	if _, err := io.ReadFull(r, dataBuf); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	// We skip verifying the server signature for now, as we trust the Server over mTLS

	envelope := &sliverpb.Envelope{}
	if err := proto.Unmarshal(dataBuf, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return envelope, nil
}
