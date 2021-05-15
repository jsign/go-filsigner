package secp256k1

import (
	"github.com/dchest/blake2b"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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