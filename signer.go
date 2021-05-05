package signer

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dchest/blake2b"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/jsign/bls/g1pubs"

	"encoding/hex"
)

func Sign(lotusExportedPK string, msg []byte) (*crypto.Signature, error) {
	ki, err := decodeLotusExportedPK(lotusExportedPK)
	if err != nil {
		return nil, fmt.Errorf("decoding lotus exported key: %s", err)
	}

	switch ki.Type {
	case types.KTSecp256k1:
		return signSecp256k1(ki.PrivateKey, msg)
	case types.KTBLS:
		return signBLS(ki.PrivateKey, msg)
	default:
		return nil, fmt.Errorf("signature type not supported")
	}
}

// Pure-go secp256k1 signer!
// This has a problem. The serialization format used in `filecoin-project/go-crypto`,
// is R||S||V to allow for self-verifying signatures. But btcec doesn't
// return V. For now it appends always V=0, but V can be 0 or 1, this should
// be calculated correctly.
// Lotus uses `filecoin-project/go-crypto` which ends up using
// https://github.com/ipsn/go-secp256k1/blob/9d62b9f0bc52d16160f79bfb84b2bbf0f6276b03/secp256.go#L53
func signSecp256k1(pk []byte, msg []byte) (*crypto.Signature, error) {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	msgHash := blake2b.Sum256(msg)
	sig, err := priv.Sign(msgHash[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %s", err)
	}
	return &crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: serializeSecp256k1Signature(sig),
	}, nil
}

// Not working yet.
func signBLS(pk []byte, msg []byte) (*crypto.Signature, error) {
	var apk [32]byte
	copy(apk[:], pk)

	sk := g1pubs.DeserializeSecretKey(apk)
	if sk.GetFRElement() == nil {
		return nil, fmt.Errorf("wrong private key")
	}
	sig := g1pubs.Sign(msg, sk)
	sigRaw := sig.Serialize()

	return &crypto.Signature{
		Type: crypto.SigTypeBLS,
		Data: sigRaw[:],
	}, nil
}

func serializeSecp256k1Signature(sig *btcec.Signature) []byte {
	sigBytes := make([]byte, 65)
	rBytes := sig.R.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	sBytes := sig.S.Bytes()
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigBytes[64] = 0 // TODO: calculate correct V? see secp256k1 method comment.
	return sigBytes
}

func decodeLotusExportedPK(lotusExportedPK string) (*types.KeyInfo, error) {
	kiBytes, err := hex.DecodeString(lotusExportedPK)
	if err != nil {
		return nil, fmt.Errorf("decoding hex: %s", err)
	}
	var ki types.KeyInfo
	if err := json.Unmarshal(kiBytes, &ki); err != nil {
		return nil, fmt.Errorf("unmarshaling exported key: %s", err)
	}

	return &ki, nil
}
