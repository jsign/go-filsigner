package secp256k1

import (
	"bytes"
	"fmt"

	"github.com/dchest/blake2b"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/filecoin-project/go-address"
)

// Sign creates a secp256k1 signature of a message using a private key.
// The private byte slice should be exactly as implemented in an
// official Filecoin client. The signature is also compatible with a Filecoin
// client. It has format R|S|V where V is 0 or 1, allowing recovering the
// public key only using the signature.
func Sign(pk []byte, msg []byte) ([]byte, error) {
	priv := secp256k1.PrivKeyFromBytes(pk)
	msgHash := blake2b.Sum256(msg)
	sig := ecdsa.SignCompact(priv, msgHash[:], false)

	// We need to left-rotate by 1 byte, and adjust the
	// recovery ID to be zero-centered.
	recoveryID := sig[0]
	copy(sig, sig[1:])
	sig[64] = recoveryID - 27

	return sig, nil
}

// Verify verifies that a message is correctly signed by a public key.
func Verify(pubkey, msg, sig []byte) bool {
	// We need to do the inverse operation of signatures.b
	recoveryID := sig[64] + 27
	copy(sig[1:], sig)
	sig[0] = recoveryID

	msgHash := blake2b.Sum256(msg)
	vpubkey, _, err := ecdsa.RecoverCompact(sig, msgHash[:])
	if err != nil {
		return false
	}
	verifAddr, err := address.NewSecp256k1Address(vpubkey.SerializeUncompressed())
	if err != nil {
		return false
	}
	if !bytes.Equal(verifAddr.Payload(), pubkey) {
		return false
	}
	return true
}

// GetPubKey returns the public key from the private key.
func GetPubKey(pk []byte) (address.Address, error) {
	priv := secp256k1.PrivKeyFromBytes(pk)
	pubkey := priv.PubKey()

	addr, err := address.NewSecp256k1Address(pubkey.SerializeUncompressed())
	if err != nil {
		return address.Undef, fmt.Errorf("generating public key: %s", err)
	}

	return addr, nil
}
