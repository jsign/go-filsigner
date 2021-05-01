package signer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecp256k1Sign(t *testing.T) {
	pkBase64 := "k5Pyv3qH2sIXcCYZXYOWuE1I2n2UE9ChaUklN6iZWcE="
	pk, err := base64.StdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)
	msg := []byte("DUKEDUKEDUKEDUKE")

	sig, err := SignSecp256k1(pk, msg)
	require.NoError(t, err)

	sigm, err := sig.MarshalBinary()
	require.NoError(t, err)
	fmt.Printf("Message: %s\n", hex.EncodeToString(msg))
	fmt.Printf("Signed message: %s\n", hex.EncodeToString(sigm))
}
