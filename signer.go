package signer

import (
	"encoding/json"
	"fmt"

	"github.com/dchest/blake2b"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/jsign/bls/g1pubs"

	"encoding/hex"
)

// Sign generates a signature for a Filecoin public address.
// Both Secp256k1 and BLS private keys can be used. Private keys are expected
// to be
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

func signSecp256k1(pk []byte, msg []byte) (*crypto.Signature, error) {
	priv := secp256k1.PrivKeyFromBytes(pk)
	msgHash := blake2b.Sum256(msg)
	sig := ecdsa.SignCompact(priv, msgHash[:], false)

	// We need to left-rotate by 1 byte, and adjust the
	// recovery ID to be zero-centered.
	recoveryID := sig[0]
	copy(sig, sig[1:])
	sig[64] = recoveryID - 27

	return &crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: sig,
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
