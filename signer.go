package signer

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dchest/blake2b"
	"github.com/filecoin-project/go-state-types/crypto"
)

// Pure-go secp256k1 signer.
// Main problem with this is that Lotus encodes signature
// with the R || S || V format. We don't have V here.
func SignSecp256k1(pk []byte, msg []byte) (crypto.Signature, error) {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	msgHash := blake2b.Sum256(msg)
	sig, err := priv.Sign(msgHash[:])
	if err != nil {
		return crypto.Signature{}, fmt.Errorf("signing: %s", err)
	}
	return crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: serializeSig(sig),
	}, nil
}

// TODO: byte65 should be fixed. it's V for self validating
// signature.
func serializeSig(sig *btcec.Signature) []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	sigBytes := make([]byte, 65)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}
