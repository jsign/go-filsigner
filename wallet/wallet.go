package wallet

import (
	"encoding/json"
	"fmt"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/jsign/go-filsigner/bls"
	"github.com/jsign/go-filsigner/secp256k1"

	"encoding/hex"
)

// WalletSign allows to sign a message using an exported private key. The exported private key
// is a hex-encoded string of a sepc256k1 or BLS private key as exported by a Filecoin
// client (e.g: `lotus wallet export`). It automatically detects the key type and signs
// appropiately.
func WalletSign(exportedPK string, msg []byte) (*crypto.Signature, error) {
	ki, err := decodeLotusExportedPK(exportedPK)
	if err != nil {
		return nil, fmt.Errorf("decoding lotus exported key: %s", err)
	}

	switch ki.Type {
	case types.KTSecp256k1:
		sig, err := secp256k1.Sign(ki.PrivateKey, msg)
		if err != nil {
			return nil, fmt.Errorf("generating secp256k1 signature: %w", err)
		}
		return &crypto.Signature{
			Type: crypto.SigTypeSecp256k1,
			Data: sig,
		}, nil
	case types.KTBLS:
		sig, err := bls.Sign(ki.PrivateKey, msg)
		if err != nil {
			return nil, fmt.Errorf("generating bls signature: %w", err)
		}
		return &crypto.Signature{
			Type: crypto.SigTypeBLS,
			Data: sig,
		}, nil
	default:
		return nil, fmt.Errorf("signature type not supported")
	}
}

func WalletVerify(publicKey address.Address, msg []byte, sig []byte) (bool, error) {
	var signature crypto.Signature
	if err := signature.UnmarshalBinary(sig); err != nil {
		return false, fmt.Errorf("unmarshaling signature: %s", err)
	}
	switch publicKey.Protocol() {
	case address.SECP256K1:
		return secp256k1.Verify(publicKey.Payload(), msg, signature.Data), nil
	case address.BLS:
		return bls.Verify(publicKey.Payload(), msg, signature.Data), nil
	default:
		return false, fmt.Errorf("address type not supported")
	}
}

func PublicKey(lotusExportedPK string) (address.Address, error) {
	ki, err := decodeLotusExportedPK(lotusExportedPK)
	if err != nil {
		return address.Undef, fmt.Errorf("decoding lotus exported key: %s", err)
	}

	switch ki.Type {
	case types.KTSecp256k1:
		return secp256k1.GetPubKey(ki.PrivateKey)
	default:
		// TODO: support BLS.
		return address.Undef, fmt.Errorf("signature type not supported")
	}
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
