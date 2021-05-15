package bls

import (
	"encoding/binary"
	"fmt"

	curve12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

// Sign creates a BLS signature of a message using a private key.
// The private key needs to be in exact format as expected in an official
// Filecoin client, which is a big-endian encoded 32 byte scalar.
// The signature has a format as described in RFC 2.6.1.
func Sign(pk []byte, msg []byte) ([]byte, error) {
	var out [32]byte
	z0 := binary.BigEndian.Uint64(pk[0:8])
	z1 := binary.BigEndian.Uint64(pk[8:16])
	z2 := binary.BigEndian.Uint64(pk[16:24])
	z3 := binary.BigEndian.Uint64(pk[24:32])
	binary.LittleEndian.PutUint64(out[0:8], z3)
	binary.LittleEndian.PutUint64(out[8:16], z2)
	binary.LittleEndian.PutUint64(out[16:24], z1)
	binary.LittleEndian.PutUint64(out[24:32], z0)
	scalar := curve12381.NewKyberScalar().SetBytes(out[:])

	signer := bls.NewSchemeOnG2(curve12381.NewBLS12381Suite())
	s, err := signer.Sign(scalar, msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return s, nil
}
