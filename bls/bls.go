package bls

import (
	"fmt"

	curve12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls" // nolint:staticcheck
	"github.com/filecoin-project/go-address"
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

// Verify verifies that a message is correctly signed by a public key.
func Verify(pubkey, msg, sig []byte) bool {
	point := curve12381.NewGroupG1().Point()
	if err := point.UnmarshalBinary(pubkey); err != nil {
		return false
	}
	signer := bls.NewSchemeOnG2(curve12381.NewBLS12381Suite())
	if err := signer.Verify(point, msg, sig); err != nil {
		return false
	}

	return true
}

// GetPubKey returns the public key from the private key.
func GetPubKey(pk []byte) (address.Address, error) {
	var pkrev [32]byte
	for i := 0; i < 32; i++ {
		pkrev[i] = pk[32-i-1]
	}
	scalar := curve12381.NewKyberScalar().SetBytes(pkrev[:])
	pubPoint := curve12381.NewGroupG1().Point()
	pubPoint.Mul(scalar, nil)

	buf, err := pubPoint.MarshalBinary()
	if err != nil {
		return address.Address{}, fmt.Errorf("marshaling pub: %s", err)
	}
	addr, err := address.NewBLSAddress(buf)
	if err != nil {
		return address.Undef, fmt.Errorf("generating public key: %s", err)
	}

	return addr, nil
}
