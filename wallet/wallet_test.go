package wallet

import (
	"encoding/hex"
	"encoding/json"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/jsign/go-filsigner/bls"
	"testing"

	"github.com/filecoin-project/go-address"
	"github.com/stretchr/testify/require"
)

var msg = []byte("DUKE") // 44554b45 in hex.

func TestSecp256k1(t *testing.T) {
	address.CurrentNetwork = address.Mainnet
	t.Parallel()

	publicAddr := "f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sa"

	// lotus wallet export f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sa
	privateKeyHex := "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226b35507976337148327349586343595a58594f5775453149326e32554539436861556b6c4e36695a5763453d227d"

	// lotus wallet sign f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sa 44554b45
	hexSignature := "0103bff286f1371c1a4ce8e33c29d6a20eeb53f17970190d12c5a1c0fc4be9a56e766250d5a82dda2179fa90ae297696d1dfaa9eea8f2f833da0cf87b927294eb700"

	t.Run("sign", func(t *testing.T) {
		t.Parallel()

		sig, err := WalletSign(privateKeyHex, msg)
		require.NoError(t, err)
		sigm, err := sig.MarshalBinary()
		require.NoError(t, err)
		genHexSignature := hex.EncodeToString(sigm)

		require.Equal(t, hexSignature, genHexSignature)
	})

	t.Run("verify", func(t *testing.T) {
		t.Parallel()

		// Check that signature verification succeeds with correct: signature, message, and public key.
		sig, err := hex.DecodeString(hexSignature)
		require.NoError(t, err)
		addr, err := address.NewFromString(publicAddr)
		require.NoError(t, err)
		okSig, err := WalletVerify(addr, msg, sig)
		require.NoError(t, err)
		require.True(t, okSig)

		// Check that signature verification fails with incorrect message.
		okSig, err = WalletVerify(addr, []byte("DUKEZ"), sig)
		require.NoError(t, err)
		require.False(t, okSig)

		// Check that address parsing fails with incorrect public key.
		_, err = address.NewFromString("f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sb")
		require.Error(t, err)
	})

	t.Run("gen-pubkey", func(t *testing.T) {
		addr, err := PublicKey(privateKeyHex)
		require.NoError(t, err)
		require.Equal(t, publicAddr, addr.String())
	})
}

func checkBlsVerify(t *testing.T, signatureBytes string, addr string, messageBytes string, expectSuccess bool) {
	sig, err := hex.DecodeString(signatureBytes)
	require.NoError(t, err)
	a, err := address.NewFromString(addr)
	require.NoError(t, err)
	data := []byte(messageBytes)
	s := crypto.Signature{
		Type: crypto.SigTypeBLS,
		Data: sig,
	}
	b, err := s.MarshalBinary()
	require.NoError(t, err)
	okSig, err := WalletVerify(a, data, b)
	if expectSuccess {
		require.NoError(t, err)
		require.True(t, okSig)
	} else {
		require.NoError(t, err)
		require.False(t, okSig)
	}
}

func TestBLSSign(t *testing.T) {
	address.CurrentNetwork = address.Mainnet
	t.Parallel()

	publicAddr := "f3rpskqryflc2sqzzzu7j2q6fecrkdkv4p2avpf4kyk5u754he7g6cr2rbpmif7pam5oxbme2oyzot4ry3d74q"

	// lotus wallet export f3rpskqryflc2sqzzzu7j2q6fecrkdkv4p2avpf4kyk5u754he7g6cr2rbpmif7pam5oxbme2oyzot4ry3d74q
	privateKeyHex := "7b2254797065223a22626c73222c22507269766174654b6579223a226862702f794666527439514c43716b6d566171415752436f50556777314b776971716e73684e49704e57513d227d"

	// lotus wallet sign f3rpskqryflc2sqzzzu7j2q6fecrkdkv4p2avpf4kyk5u754he7g6cr2rbpmif7pam5oxbme2oyzot4ry3d74q 44554b45
	hexSignature := "0280cef41af956cf6855725a5af0d8d956ea41f6da2688cc1f436a7ea5ebd15d96ba384746b819c0836c53a54d6d30b0a70b528204e9da92f833031e7a4776f57bad83e033ea0235bad0f8a5337a4eb66870fc0429175ed63f91203ec1b65c6e31"

	t.Run("sign", func(t *testing.T) {
		t.Parallel()

		sig, err := WalletSign(privateKeyHex, msg)
		require.NoError(t, err)
		sigm, err := sig.MarshalBinary()
		require.NoError(t, err)
		genHexSignature := hex.EncodeToString(sigm)

		require.Equal(t, hexSignature, genHexSignature)
	})

	t.Run("gen-pubkey", func(t *testing.T) {
		addr, err := PublicKey(privateKeyHex)
		require.NoError(t, err)
		require.Equal(t, publicAddr, addr.String())
	})

	t.Run("verify", func(t *testing.T) {
		t.Parallel()

		// Check that signature verification succeeds with correct: signature, message, and public key.
		sig, err := hex.DecodeString(hexSignature)
		require.NoError(t, err)
		addr, err := address.NewFromString(publicAddr)
		require.NoError(t, err)
		okSig, err := WalletVerify(addr, msg, sig)
		require.NoError(t, err)
		require.True(t, okSig)

		// Check that signature verification fails with incorrect message.
		okSig, err = WalletVerify(addr, []byte("DUKEZ"), sig)
		require.NoError(t, err)
		require.False(t, okSig)

		// Check that signature verification fails with incorrect public key.
		wrongAddr, err := address.NewFromString("f3wmv7nhiqosmlr6mis2mr4xzupdhe3rtvw5ntis4x6yru7jhm35pfla2pkwgwfa3t62kdmoylssczmf74yika")
		require.NoError(t, err)
		okSig, err = WalletVerify(wrongAddr, msg, sig)
		require.NoError(t, err)
		require.False(t, okSig)

	})

	// https://github.com/filecoin-project/lotus/blob/97a9921cdd807278414440dc041f567b6e3fb8d0/lib/sigs/bls/bls_test.go#L39
	t.Run("test-uncompressed-fails", func(t *testing.T) {
		t.Parallel()

		data := "potato"
		addr := "f3tcgq5scpfhdwh4dbalwktzf6mbv3ng2nw7tyzni5cyrsgvineid6jybnweecpa6misa6lk4tvwtxj2gkwpzq"
		// compressed
		signature := "9927444bfcffdca34af57b78757b9b90f1cd28d2a3aeed2aa6bde299f8bbb9184756f2287b0588e6d3f2860d2bb2066e0c59778c1e644fb2cfb35fba8f09fa824a9ed825108c82ff4bf634c1037eeaf185f45673d4a1c1c6eeb712b7d72a5498"
		checkBlsVerify(t, signature, addr, data, true)
		// compressed byte changed
		signature = "9927444bfcffdca34af57b78757b9b90f1cd28d2a3aeed2aa6bde299f8bbb9184756f2287b0588f6d3f2860d2bb2066e0c59778c1e644fb2cfb35fba8f09fa824a9ed825108c82ff4bf634c1037eeaf185f45673d4a1c1c6eeb712b7d72a5498"
		checkBlsVerify(t, signature, addr, data, false)
		// compressed with prefix
		signature = "9927444bfcffdca34af57b78757b9b90f1cd28d2a3aeed2aa6bde299f8bbb9184756f2287b0588e6d3f2860d2bb2066e0c59778c1e644fb2cfb35fba8f09fa824a9ed825108c82ff4bf634c1037eeaf185f45673d4a1c1c6eeb712b7d72a549855"
		checkBlsVerify(t, signature, addr, data, false)
		// uncompressed
		signature = "1927444bfcffdca34af57b78757b9b90f1cd28d2a3aeed2aa6bde299f8bbb9184756f2287b0588e6d3f2860d2bb2066e0c59778c1e644fb2cfb35fba8f09fa824a9ed825108c82ff4bf634c1037eeaf185f45673d4a1c1c6eeb712b7d72a549808942378dbce2ad72e87df083b66c631c18c582f9f9e104d2a7e13e79cbb22deccf67777b09c255d5de688098c6335d40a85768db766a6c6ece6de2a9f3487281a48fecab14702f6512652709d7edb7e8bc9f641aaa83b7e8afd7ae479e659e4"
		checkBlsVerify(t, signature, addr, data, false)
		// uncompressed one byte change
		signature = "1927444bfcffdca34af57b78757b9b90f1cd28d2a3aeed2aa6bde299f8bbb9184756f2287b0588e6d3f2860d2bb2066e0c59778c1e644fb2cfb35fba8f09fa824a9ed825108c82ff4bf634c1037eeaf185f45673d4a1c1c6eeb712b7d72a549808942378dbce2ad72e87df083b66c631c18c582f9f9e104d2a7e13e79cbb22deccf67777b09c255d5de688098c6335d40a85668db766a6c6ece6de2a9f3487281a48fecab14702f6512652709d7edb7e8bc9f641aaa83b7e8afd7ae479e659e4"
		checkBlsVerify(t, signature, addr, data, false)
	})

	t.Run("zero-point", func(t *testing.T) {
		t.Parallel()
		// Create Zero point private and public key
		var key [32]byte
		ki := KeyInfo{
			Type:       KTBLS,
			PrivateKey: key[:],
		}
		addr, err := bls.GetPubKey(ki.PrivateKey)
		require.NoError(t, err)
		require.Equal(t, "f3yaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaby2smx7a", addr.String())
		m, err := json.Marshal(ki)
		require.NoError(t, err)
		pk := hex.EncodeToString([]byte(m))

		// Sign with Zero point private key should fail
		sig, err := WalletSign(pk, []byte("hello"))
		require.Error(t, err)
		require.Nil(t, sig)

		// Verify signature with Zero point public key should fail
		signatureHex := "02c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		sigBytes, err := hex.DecodeString(signatureHex)
		require.NoError(t, err)
		result, err := WalletVerify(addr, []byte("hello"), sigBytes)
		require.Error(t, err)
		require.False(t, result)
	})
}
