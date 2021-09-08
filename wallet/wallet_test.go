package wallet

import (
	"encoding/hex"
	"testing"

	"github.com/filecoin-project/go-address"
	"github.com/stretchr/testify/require"
)

var msg = []byte("DUKE") // 44554b45 in hex.

func TestSecp256k1(t *testing.T) {
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

		// Check that signature verification fails with incorrect public key.
		wrongAddr, err := address.NewFromString("f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sb")
		require.NoError(t, err)
		okSig, err = WalletVerify(wrongAddr, msg, sig)
		require.NoError(t, err)
		require.False(t, okSig)
	})

	t.Run("gen-pubkey", func(t *testing.T) {
		addr, err := PublicKey(privateKeyHex)
		require.NoError(t, err)
		require.Equal(t, publicAddr, addr.String())
	})
}

func TestBLSSign(t *testing.T) {
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
}
