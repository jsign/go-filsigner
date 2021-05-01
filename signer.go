package signer

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dchest/blake2b"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/phoreproject/bls/g1pubs"
)

// Pure-go secp256k1 signer.
// Main problem with this is that Lotus relies on signatures
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
		Data: serializeSecp256k1Signature(sig),
	}, nil
}

func serializeSecp256k1Signature(sig *btcec.Signature) []byte {
	sigBytes := make([]byte, 65)
	rBytes := sig.R.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	sBytes := sig.S.Bytes()
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigBytes[64] = 0 // TODO: V?
	return sigBytes
}

func SignBLS(pk []byte, msg []byte) (crypto.Signature, error) {
	var apk [32]byte
	copy(apk[:], pk)

	sk := g1pubs.DeriveSecretKey(apk)
	sig := g1pubs.Sign(msg, sk)
	sigRaw := sig.Serialize()

	return crypto.Signature{
		Type: crypto.SigTypeBLS,
		Data: sigRaw[:],
	}, nil
}
