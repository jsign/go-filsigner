module github.com/jsign/go-filsigner

go 1.16

require (
	github.com/dchest/blake2b v1.0.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.0-20210507181900-4e0be8d2fbb4
	github.com/filecoin-project/go-state-types v0.1.0
	github.com/filecoin-project/lotus v1.8.0
	github.com/jsign/bls v0.0.0-20210505222336-ece047ccd126
	github.com/stretchr/testify v1.7.0
)

//replace github.com/jsign/bls => ../bls
