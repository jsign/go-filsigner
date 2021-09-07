package bls

import (
	"fmt"

	curve12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls" // nolint:staticcheck
)

// Sign creates a BLS signature of a message using a private key.
// The private key needs to be in exact format as expected in an official
// Filecoin client, which is a big-endian encoded 32 byte scalar.
// The signature has a format as described in RFC 2.6.1.
func Sign(pk []byte, msg []byte) ([]byte, error) {
	// We need to do an endianess conversion considering
	// Filecoin assumptions around the private key representation.
	var pkrev [32]byte
	for i := 0; i < 32; i++ {
		pkrev[i] = pk[32-i-1]
	}
	scalar := curve12381.NewKyberScalar().SetBytes(pkrev[:])
	signer := bls.NewSchemeOnG2(curve12381.NewBLS12381Suite())
	s, err := signer.Sign(scalar, msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return s, nil
}
