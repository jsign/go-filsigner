package bls

import (
	"fmt"

	curve12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

// Sign creates a BLS signature of a message using a private key.
// The private key needs to be in exact format as expected in an official
// Filecoin client, which is a big-endian encoded 32 byte scalar.
// The signature has a format as described in RFC 2.6.1.
func Sign(pk []byte, msg []byte) ([]byte, error) {
	for i := 0; i < 16; i++ {
		pk[i], pk[32-i-1] = pk[32-i-1], pk[i]
	}
	scalar := curve12381.NewKyberScalar().SetBytes(pk)
	signer := bls.NewSchemeOnG2(curve12381.NewBLS12381Suite())
	s, err := signer.Sign(scalar, msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return s, nil
}
