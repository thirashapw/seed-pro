package main

import (
	"crypto/rand"
	"math/big"
)

// Generate 12 random words
func random12Words() []string {
	words := make([]string, 12)
	for i := 0; i < 12; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(Bip39WordList))))
		words[i] = Bip39WordList[idx.Int64()]
	}
	return words
}
