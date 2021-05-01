package signer

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecp256k1Sign(t *testing.T) {
	// lotus wallet export f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sa
	pk64 := "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226b35507976337148327349586343595a58594f5775453149326e32554539436861556b6c4e36695a5763453d227d"
	lotusFormatSig := testSign(t, pk64)

	// lotus wallet sign f1fib3pv7jua2ockdugtz7viz3cyy6lkhh7rfx3sa 44554b45
	require.Equal(t, "0103bff286f1371c1a4ce8e33c29d6a20eeb53f17970190d12c5a1c0fc4be9a56e766250d5a82dda2179fa90ae297696d1dfaa9eea8f2f833da0cf87b927294eb700", lotusFormatSig)
}

func TestBLSSign(t *testing.T) {
	// lotus wallet export f3rpskqryflc2sqzzzu7j2q6fecrkdkv4p2avpf4kyk5u754he7g6cr2rbpmif7pam5oxbme2oyzot4ry3d74q
	pk64 := "7b2254797065223a22626c73222c22507269766174654b6579223a226862702f794666527439514c43716b6d566171415752436f50556777314b776971716e73684e49704e57513d227d"
	lotusFormatSig := testSign(t, pk64)

	// lotus wallet sign f3rpskqryflc2sqzzzu7j2q6fecrkdkv4p2avpf4kyk5u754he7g6cr2rbpmif7pam5oxbme2oyzot4ry3d74q 44554b45
	require.Equal(t, "0280cef41af956cf6855725a5af0d8d956ea41f6da2688cc1f436a7ea5ebd15d96ba384746b819c0836c53a54d6d30b0a70b528204e9da92f833031e7a4776f57bad83e033ea0235bad0f8a5337a4eb66870fc0429175ed63f91203ec1b65c6e31", lotusFormatSig)
}

func testSign(t *testing.T, lotusExportedPK string) string {
	t.Helper()
	msg := []byte("DUKE")

	sig, err := Sign(lotusExportedPK, msg)
	require.NoError(t, err)

	sigm, err := sig.MarshalBinary()
	require.NoError(t, err)
	return hex.EncodeToString(sigm)
}
