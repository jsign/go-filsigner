package secp256k1

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

var sink []byte

func BenchmarkSign(b *testing.B) {
	pk := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, pk)
	require.NoError(b, err)

	msg := []byte("duke+jsign")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink, _ = Sign(pk, msg)
	}
}
